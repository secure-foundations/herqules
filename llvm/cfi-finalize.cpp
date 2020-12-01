#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/InitializePasses.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/AlwaysInliner.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#ifndef NDEBUG
#include "llvm/IR/Verifier.h"
#endif

#include <deque>
#include <unordered_map>
#include <utility>

#include "config.h"

#include "cfi-finalize.h"
#include "cfi-init.h"
#include "utils.h"

#define DEBUG_TYPE "cfi-finalize"

// Second LLVM pass that handles calls to builtin memory functions, e.g.
// memcpy(), etc, performs dominated store elision, removes unneeded
// messages, and adds stack return address protection.
// It shouldn't run too early, because CFG simplification will sink stores on
// both sides of a conditional expression into a single store of a PHI in the
// exit block, which improves effectiveness of dominated load elision. Likewise,
// it shouldn't run before function inlining, because that will expose
// consecutive defines/invalidates in e.g. C++ constructor/destructor class
// hierarchies that can be optimized. As a result, run this pass at
// EP_OptimizerLast or EP_FullLinkTimeOptimizationLast, depending on whether LTO
// is enabled.
// This pass will also inline message functions with the interface's
// implementation, after all optimizations have completed, if enabled.

using namespace llvm;

static cl::opt<bool>
    LTOTime("run-cfi-finalize-lto",
            cl::desc("Run CFI finalize pass at LTO-time (default = true = "
                     "LTO-time, false = compile-time)"),
            cl::init(true));

cl::opt<bool> RunCFIRetAddr("run-cfi-retaddr",
                            cl::desc("Enable CFI instrumentation for stack "
                                     "return addresses (default = false)"),
                            cl::init(false));

static cl::opt<bool> SkipCXXVirtualError(
    "cfi-skip-virtual-error",
    cl::desc("Skip error handlers for C++ virtual functions (default = true)"),
    cl::init(true));

static cl::opt<bool>
    UseCallGraphAnalysis("hq-callgraph-analysis",
                         cl::desc("Use callgraph analysis results to elide "
                                  "pointer loads (default = true)"),
                         cl::init(true));

// Ensure statistics are defined even in release mode
#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
STATISTIC(NumVTGlobal, "Number of instrumented global objects");
STATISTIC(NumFPGlobal, "Number of instrumented global function pointers");
STATISTIC(NumIntGlobal, "Number of instrumented internal global references");
STATISTIC(NumExtGlobal, "Number of instrumented external global references");
STATISTIC(NumOptDef, "Number of pointer defines optimized away");
STATISTIC(NumOptChk, "Number of pointer checks optimized away");
STATISTIC(NumChkInv, "Number of optimized pointer check-invalidates");
STATISTIC(NumOptInv, "Number of pointer invalidates optimized away");
STATISTIC(NumRecGuards, "Number of created recursion guards");
STATISTIC(NumCopyMove, "Number of pointer copies/moves");
STATISTIC(NumFree, "Number of pointer frees");
STATISTIC(NumRetDefs, "Number of return pointer defines");
STATISTIC(NumRetChks, "Number of return pointer checks");
#else
static unsigned int NumVTGlobal = 0, NumFPGlobal = 0, NumIntGlobal = 0,
                    NumExtGlobal = 0, NumOptDef = 0, NumOptChk = 0,
                    NumChkInv = 0, NumOptInv = 0, NumRecGuards = 0,
                    NumCopyMove = 0, NumFree = 0, NumRetDefs = 0,
                    NumRetChks = 0;
#endif /* !NDEBUG || LLVM_ENABLE_STATS */

/* Types */
using DominatorCallback = function_ref<DominatorTree *(Function &F)>;

/* Helper functions */
// Given a pointer, return its root variable, if it doesn't alias
static const Value *getRootVariable(const Value *Pointer) {
    DedupVector<const Value *, 2> Stack;

    Pointer = simplify(Pointer, false);
    Stack.push_back(Pointer);
    while (!Stack.empty()) {
        auto *V = Stack.pop_back_val();

        // Initial check for aliasing on the destination variable
        if (auto *BCO = dyn_cast<BitCastOperator>(V)) {
            // Argument is a cast expression, resolve it and recurse
            Stack.push_back(BCO->getOperand(0));
        } else if (auto *A = dyn_cast<Argument>(V)) {
            if (!A->hasNoAliasAttr())
                return nullptr;
        } else if (auto *CB = dyn_cast<CallBase>(V)) {
            if (auto *II = dyn_cast<IntrinsicInst>(CB)) {
                switch (II->getIntrinsicID()) {
                case Intrinsic::lifetime_start:
                case Intrinsic::lifetime_end:
                    continue;
                // Ignore invariant.group intrinsics
                case Intrinsic::launder_invariant_group:
                case Intrinsic::strip_invariant_group:
                    Stack.push_back(II->getArgOperand(0));
                    continue;
                }
            }

            // Allocations do not alias
            if (!CB->returnDoesNotAlias())
                return nullptr;
        } else if (auto *GV = dyn_cast<GlobalVariable>(V)) {
            // May be accessible from other functions, regardless of LTO
            if (!GV->hasLocalLinkage())
                return nullptr;
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            // May alias with another subfield
            if (!GEP->hasAllConstantIndices() || !GEP->isInBounds())
                return nullptr;
            // Recurse on the parent variable
            Stack.push_back(GEP->getPointerOperand());
        } else if (isa<AllocaInst>(V) || isa<ConstantPointerNull>(V) ||
                   isa<UndefValue>(V)) {
            // Variable is a stack allocation, null pointer, or undefined value,
            // which don't alias
            continue;
        } else if (auto *PN = dyn_cast<PHINode>(V)) {
            // Recurse on all incoming values
            for (Value *IV : PN->incoming_values())
                Stack.push_back(IV);
        } else if (auto *SI = dyn_cast<SelectInst>(V)) {
            // Recurse on all incoming values
            for (unsigned i = 1; i < SI->getNumOperands(); ++i)
                Stack.push_back(SI->getOperand(i));
        } else if (isa<IntToPtrOperator>(V) || isa<LoadInst>(V)) {
            // Unknown variable
            return nullptr;
        } else if (isa<ExtractElementInst>(V) || isa<InsertElementInst>(V)) {
            // FIXME: Unsupported
            return nullptr;
        } else {
            errs() << "V: " << *V << "\n";
            report_fatal_error("getRootVariable(): Unsupported pointer!\n");
        }
    }

    return Pointer;
}

static bool isUsed(DedupVector<const Value *, 2> &Stack, const Value &Val,
                   const Function &F,
                   const SmallSet<Instruction *, 1> &Remove) {
    Stack.clear();
    Stack.push_back(&Val);
    while (!Stack.empty()) {
        auto *V = Stack.pop_back_val();

        for (auto *U : V->users()) {
            if (isa<Instruction>(U) && Remove.count(cast<Instruction>(U))) {
                continue;
            } else if (auto *CB = dyn_cast<CallBase>(U)) {
                if (CB->getCalledFunction() == &F)
                    continue;
            } else if (auto *BCO = dyn_cast<BitCastOperator>(U)) {
                Stack.push_back(BCO);
                continue;
            } else if (auto *GEP = dyn_cast<GEPOperator>(U)) {
                if (resolveGEP(GEP) == U) {
                    Stack.push_back(GEP);
                    continue;
                }
            }

            return true;
        }
    }

    return false;
}

// Determine if a check is removable, given the pointer and value. It is
// removable if either is never used, or if the value is a direct call.
// These can occur due to an intermediate optimization pass.
static bool isRemovableCheck(const Value &A0, const Value &A1,
                             const Function &PCF,
                             const SmallSet<Instruction *, 1> &Remove) {
    bool Ret = true;
    DedupVector<const Value *, 2> Stack;

    // Loaded value is never used
    if (!isUsed(Stack, A1, PCF, Remove))
        return true;

    // Pointer and value can be different after inlining. Check if pointer never
    // escapes and is ever used
    auto *Root = getRootVariable(&A0);
    if (Root && !isUsed(Stack, *Root, PCF, Remove))
        return true;

    Stack.clear();
    Stack.push_back(&A1);
    while (Ret && !Stack.empty()) {
        auto *V = simplify(Stack.pop_back_val());

        if (isa<Instruction>(V) && Remove.count(cast<Instruction>(V))) {
            continue;
        } else if (isa<AllocaInst>(V) || isa<IntToPtrOperator>(V)) {
            // Argument is a stack variable or casted integer, not removable
            Ret = false;
        } else if (isa<Argument>(V) || isa<CallBase>(V)) {
            // Argument is a removable argument or return value only if it is a
            // function pointer, because those are checked in the caller
            Ret = isFunctionPointerTy(*V->getType());
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            // Argument is a GEP expression, attempt to resolve it
            auto *V = resolveGEP(GEP);
            if (V)
                Stack.push_back(V);
            else
                Ret = false;
        } else if (isa<ConstantExpr>(V) || isa<ConstantPointerNull>(V) ||
                   isa<Function>(V) || isa<UndefValue>(V)) {
            // Argument is a constant or pointer value, removable
            Ret = true;
        } else if (auto *GV = dyn_cast<GlobalVariable>(V)) {
            // Argument is a global variable value, removable if
            // constant
            Ret = GV->isConstant();
        } else if (auto *LI = dyn_cast<LoadInst>(V)) {
            // Argument is a load expression, resolve it and recurse
            Stack.push_back(LI->getPointerOperand());
        } else if (auto *PN = dyn_cast<PHINode>(V)) {
            // Argument is a PHINode value, recurse
            for (Value *IV : PN->incoming_values())
                Stack.push_back(IV);
        } else if (auto *SI = dyn_cast<SelectInst>(V)) {
            // Argument is a SelectInst value, recurse
            for (unsigned i = 1; i < SI->getNumOperands(); ++i)
                Stack.push_back(SI->getOperand(i));
        } else if (isa<ExtractElementInst>(V) || isa<InsertElementInst>(V)) {
            // Argument is unsupported
            return false;
        } else {
            if (V)
                errs() << "V: " << *V << "\n";
            report_fatal_error("isRemovableCheck(): Unsupported value!");
        }
    }

    return Ret;
}

// Determine if an invalidate is removable, given the pointer. It is removable
// if it has already been invalidated, or if it is no longer a sensitive pointer
// because an intermediate optimization pass may have simplified the original
// constructor or it may have been devirtualized.
static bool isRemovableInvalidate(
    const CallBase &IC, const Function &PDF, const DominatorTree *DT,
    const std::unordered_map<const Value *, SmallSet<const CallBase *, 2>>
        &InvalidatedObjs,
    const SmallSet<Instruction *, 1> &Remove) {
    auto *Ptr = const_cast<Value *>(simplify(IC.getArgOperand(0)));

    auto It = InvalidatedObjs.find(Ptr);
    if (DT && It != InvalidatedObjs.end()) {
        for (auto *CB : It->second)
            if (DT->dominates(CB, &IC))
                return true;
    }

    auto *Root = getRootVariable(Ptr);
    if (!Root)
        return false;

    DedupVector<const Value *, 4> Stack;
    Stack.push_back(Root);
    while (!Stack.empty()) {
        auto *V = Stack.pop_back_val();

        for (auto &U : V->uses()) {
            auto *UU = U.getUser();

            if (isa<Instruction>(UU) && Remove.count(cast<Instruction>(UU))) {
                continue;
            } else if (auto *CB = dyn_cast<CallBase>(UU)) {
                if (auto *II = dyn_cast<IntrinsicInst>(CB)) {
                    switch (II->getIntrinsicID()) {
                    case Intrinsic::lifetime_start:
                    case Intrinsic::lifetime_end:
                        continue;
                    // Ignore invariant.group intrinsics
                    case Intrinsic::launder_invariant_group:
                    case Intrinsic::strip_invariant_group:
                        assert(II->getArgOperand(0) == V &&
                               "Invariant group must be on the argument!");
                        Stack.push_back(II);
                        continue;
                        break;
                    }
                }

                Function *F = CB->getCalledFunction();
                if (CB->isArgOperand(&U)) {
                    const unsigned OpNum = U.getOperandNo();
                    if (!CB->doesNotCapture(OpNum) ||
                        (F == &PDF && OpNum == 0)) {
                        // Argument is captured or pointer is defined on the
                        // object
                        return false;
                    } else if (F) {
                        const Optional<std::string> Name =
                            getDemangledName(F->getName());
                        if (Name && isConstructor(*Name)) {
                            // A constructor is called on the object
                            return false;
                        }
                    }
                }
            } else if (auto *BCO = dyn_cast<BitCastOperator>(UU)) {
                assert(BCO->getOperand(0) == V &&
                       "Cast must be from the variable!");
                // Argument is a cast expression, resolve it and recurse
                Stack.push_back(BCO);
            } else if (auto *GEP = dyn_cast<GEPOperator>(UU)) {
                assert(GEP->getPointerOperand() == V &&
                       "GEP must be on the variable!");
                // Access is to the same or unknown offset
                if (resolveGEP(GEP) == V || !GEP->isInBounds() ||
                    !GEP->hasAllConstantIndices()) {
                    Stack.push_back(GEP);
                    continue;
                }

                // Access is to a different offset of the variable
                continue;
            } else if (isa<PHINode>(UU) || isa<SelectInst>(UU)) {
                // Aliases with other values in subsequent uses
                return false;
            } else if (auto *SI = dyn_cast<StoreInst>(UU)) {
                // Variable address must not escape
                if (SI->getValueOperand() == V)
                    return false;
            } else if (auto *RI = dyn_cast<ReturnInst>(UU)) {
                assert(RI->getReturnValue() == V &&
                       "Return must be of the variable!");
                // Variable escapes into calling functions
                return false;
            } else if (auto *LI = dyn_cast<LoadInst>(UU)) {
                assert(LI->getPointerOperand() == V &&
                       "Load must be from the variable!");
                // Argument is loaded from, ignore it
            } else if (isa<ICmpInst>(UU)) {
                // Argument is used, ignore it
                continue;
            } else if (isa<ExtractElementInst>(UU) ||
                       isa<InsertElementInst>(UU) ||
                       isa<PtrToIntOperator>(UU)) {
                // Argument is unsupported
                return false;
            } else if (UU->getNumUses()) {
                // Skip ConstantAggregates created for global variables
                if (UU)
                    errs() << "UU: " << *UU << "\n";
                report_fatal_error(
                    "isRemovableInvalidate(): Unsupported value!");
            }
        }
    }

    return true;
}

/* Call paths */
class CallPaths {
  public:
    template <typename T> using set_type = SmallSet<T, 4>;
    template <typename T>
    using iterator_type = iterator_range<typename set_type<T>::const_iterator>;
    using call_type = const CallBase *;
    using function_type = const Function *;

  private:
    CallGraph &CG;
    std::unordered_map<std::pair<function_type, function_type>,
                       set_type<call_type>>
        CallSites;
    std::unordered_map<function_type, set_type<function_type>>
        ReachableFunctions;

    void computeAllPaths(function_type F, set_type<call_type> *CS) {
        // Perform DFS to populate all reachable paths from F
        DedupVector<const CallGraphNode *, 4> Stack;
        std::unordered_map<const CallGraphNode *, unsigned> IncomingCalls;
        auto *CGN = F ? CG[F] : CG.getExternalCallingNode();
        Stack.push_back(CGN);
        while (!Stack.empty()) {
            Optional<set_type<call_type>> ParentCallSites;
            auto *GN = Stack.pop_back_val();
            auto *PF = GN->getFunction();

            // Lookup or create the set of reachable functions for this parent
            auto RFI = ReachableFunctions.find(PF);
            if (RFI == ReachableFunctions.end())
                RFI = ReachableFunctions.emplace(PF, set_type<function_type>())
                          .first;

            IncomingCalls.clear();
            // Iterate through each child callee of the parent
            for (auto &C : *GN) {
                auto *CF = C.second->getFunction();
                // Definition of CF is not available
                if (!CF || CF->isDeclaration())
                    continue;

                // If the parent is the start of the path, add its callsites
                if (CS && GN == CGN) {
                    if (!ParentCallSites)
                        ParentCallSites.emplace();
                    assert(C.first.pointsToAliveValue() &&
                           "Value handle must be valid!");
                    ParentCallSites->insert(&cast<CallBase>(*C.first));
                }

                // Count the total number of calls to the child from the parent
                IncomingCalls[C.second]++;
            }

            // Add a reference from the external calling node if the function
            // has either non-local linkage or address taken. When in LTO mode,
            // the first case can be ignored. Note that some functions can
            // initially have local linkage but later become non-local after
            // the CallGraph is constructed, so instead check non-address taken.
            if (LTOTime) {
                const auto *ECN = CG.getExternalCallingNode();
                for (auto &P : *ECN) {
                    if (!P.second->getFunction()->hasAddressTaken() &&
                        IncomingCalls.count(P.second))
                        IncomingCalls[P.second]++;
                }
            }

            // Iterate through all unique child callees of the parent
            for (auto &P : IncomingCalls) {
                auto *CF = P.first->getFunction();

                // Skip if a caller has not been visited (another path exists)
                assert(P.first->getNumReferences() >= P.second &&
                       "Callers cannot exceed maximum references!");
                if (P.first->getNumReferences() != P.second)
                    continue;

                // If the parent is the start of the path, add its callsites
                if (CS && GN == CGN && ParentCallSites)
                    *CS = *ParentCallSites;

                // Lookup the set of reachable functions for the child
                auto CFI = ReachableFunctions.find(CF);
                if (CFI != ReachableFunctions.end()) {
                    // Unify the callees of the child with that of the parent
                    RFI->second.insert(CFI->second.begin(), CFI->second.end());
                } else {
                    // Add the child to the callees of the parent, and enqueue
                    // it
                    RFI->second.insert(CF);
                    Stack.push_back(CG[CF]);
                }
            }
        }
    }

  public:
    CallPaths(CallGraph &C, bool skipIntrinsics = true) : CG(C) {}

    // Returns an iterator pair to the callsites in P on the path from P to C,
    // and such that there are no other paths to C.
    // When the first iterator is equal to the second, there are no remaining
    // callsites
    iterator_type<call_type> getOnlyCallPath(function_type P, function_type C) {
        // Definition of P or C is not available
        if ((P && P->isDeclaration()) || (C && C->isDeclaration())) {
            auto it = set_type<call_type>::const_iterator(nullptr, nullptr,
                                                          DebugEpochBase());
            return make_range(it, it);
        }

        auto Path = std::make_pair<>(P, C);
        // Check if result is known
        auto CSI = CallSites.find(Path);
        if (CSI != CallSites.end())
            return make_range(CSI->second.begin(), CSI->second.end());
        CSI = CallSites.emplace(Path, set_type<call_type>()).first;
        ReachableFunctions.emplace(P, set_type<function_type>());

        // Compute call paths and call sites
        computeAllPaths(P, &CSI->second);

        return make_range(CSI->second.begin(), CSI->second.end());
    }

    // Returns whether there exists a path from P to C, and such that there are
    // no other paths to C
    bool existsOnlyPath(function_type P, function_type C) {
        // Definition of P or C is not available
        if ((P && P->isDeclaration()) || (C && C->isDeclaration()))
            return false;

        // Check if result is known
        auto RFI = ReachableFunctions.find(P);
        if (RFI != ReachableFunctions.end())
            return RFI->second.count(C);
        RFI = ReachableFunctions.emplace(P, set_type<function_type>()).first;

        // Compute call paths
        computeAllPaths(P, nullptr);

        return RFI->second.count(C);
    }
};

// Given a pointer definition, find the previous instrumented store
// FIXME: Brittle instruction matching
static StoreInst *getInstrumentedStore(CallBase &D, const Value *A0,
                                       const Value *A1, bool &hasMultiple) {
    const Value *CV = D.getCalledValue();
    DedupVector<std::pair<Instruction *, const Value *>, 4> Stack;

    Stack.push_back(std::make_pair(D.getPrevNode(), A0));
    while (!Stack.empty()) {
        Instruction *I;
        const Value *P;

        std::tie(I, P) = Stack.pop_back_val();
        while (I) {
            if (auto *SI = dyn_cast<StoreInst>(I)) {
                if (simplify(SI->getPointerOperand()) == P ||
                    simplify(SI->getValueOperand()) == A1) {
                    if (!Stack.empty())
                        hasMultiple = true;
                    return SI;
                }
            } else if (auto *CB = dyn_cast<CallBase>(I)) {
                // Avoid overlapping with another define
                if (CB->getCalledValue() == CV)
                    break;
            } else if (auto *PN = dyn_cast<PHINode>(I)) {
                if (PN == P) {
                    for (unsigned i = 0; i < PN->getNumIncomingValues(); ++i)
                        Stack.push_back(std::make_pair(
                            PN->getIncomingBlock(i)->getTerminator(),
                            simplify(PN->getIncomingValue(i))));
                }
            }

            I = I->getPrevNode();
        }
    }

    return nullptr;
}

// Replace an intraprocedural dominated load L of GV with the canonical
// hoisted load for that function
static Value *getIPReplacement(
    IRBuilder<> &IRB, GlobalVariable *GV, Instruction *L, FunctionCallee &PCF,
    std::unordered_map<std::pair<const GlobalVariable *, const Function *>,
                       Instruction *> &HoistedLoads) {
    Value *NewV;
    Function *LF = L->getFunction();
    auto Pair = std::make_pair<>(GV, LF);
    // Lookup the replacement for this instruction
    auto It = HoistedLoads.find(Pair);
    if (It != HoistedLoads.end()) {
        // This is the replacement, abort
        if (L == It->second)
            return nullptr;
        NewV = It->second;
    } else {
        Value *Args[] = {GV, nullptr};
        auto *Entry = &LF->getEntryBlock();
        IRB.SetInsertPoint(L->getParent() == Entry ? L
                                                   : Entry->getTerminator());
        Args[1] = NewV = IRB.CreateLoad(GV);
        // Create a check since a race is possible
        createCastedCall(IRB, PCF, Args);
        HoistedLoads.emplace(Pair, cast<Instruction>(NewV));
    }

    return NewV;
}

// Eliminate all checks PCF on L
static void removeAllChecks(Instruction *L, Function &PCF,
                            SmallSet<Instruction *, 1> &Remove) {
    DedupVector<Value *, 4> Stack;
    Stack.push_back(L);

    while (!Stack.empty()) {
        Value *V = Stack.pop_back_val();

        for (auto &U : V->uses()) {
            User *UU = U.getUser();
            if (auto *BCO = dyn_cast<BitCastOperator>(UU)) {
                assert(BCO->getOperand(0) == V &&
                       "Cast must be from the variable!");
                Stack.push_back(BCO);
            } else if (auto *GEP = dyn_cast<GEPOperator>(UU)) {
                assert(GEP->getPointerOperand() == V &&
                       "GEP must be on the variable!");
                if (GEP->hasAllZeroIndices())
                    Stack.push_back(GEP);
            } else if (auto *CB = dyn_cast<CallBase>(UU)) {
                if (CB->getCalledFunction() == &PCF && CB->isArgOperand(&U) &&
                    U.getOperandNo() == 1) {
                    Remove.insert(CB);
                    ++NumOptChk;
                }
            }
        }
    }
}

// Given a value, copy or split its definition
static Instruction *getSplitDefinition(Value *V) {
    if (Instruction *I = dyn_cast<Instruction>(V)) {
        if (I->getNumUses() == 1) {
            I->removeFromParent();
            return I;
        } else
            return I->clone();
    } else if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V))
        return CE->getAsInstruction();
    return nullptr;
}

// Analyze operations involving an defined store from a root. Find calls to
// message functions, and dominated loads. The latter is interprocedural when
// CallPaths is given. Returns nullptr if may escape or unsupported.
// Similar functionality to dominated loads is implemented by the GVN and
// GlobalOpt + Mem2Reg passes, but if the underlying variable is a
// GlobalVariable, the former will fail due to unsupported AliasAnalysis and
// MemoryDependenceAnalysis, and the latter will require the unique calling
// function be non-recursive.
// TODO: Refactor this and isRemovableCheck() into NoEscapeVisitor
static bool analyzeDefinedStore(const DataLayout &DL, const DominatorTree &DT,
                                CallPaths *CP,
                                SmallVectorImpl<Instruction *> &Loads,
                                SmallVectorImpl<CallBase *> &LocalMessages,
                                bool &escapesReturn, bool &hasMultipleCallers,
                                bool &mayCopyFrom, bool &mayCopyTo, Value &R,
                                const StoreInst &S, APInt *Offset,
                                const SmallSet<Instruction *, 1> &Remove) {
    bool CorrectOffset = !Offset;
    const unsigned StoreSize =
        DL.getTypeStoreSize(S.getValueOperand()->getType());
    std::deque<Value *> Users;
    auto *F = S.getFunction();
    SmallVector<const Instruction *, 2> ChildStores;

    Optional<SmallSet<const CallBase *, 4>> LocalCalls;
    Optional<SmallVector<Instruction *, 2>> IPLoads;
    Optional<SmallVector<std::pair<Instruction *, bool>, 2>> IPStores;

    assert(DT.getNode(S.getParent()) && "Store must be in dominator tree!");

    // FIXME: Doesn't recurse on PHINodes or SelectInst
    if (isa<PHINode>(R) || isa<SelectInst>(R))
        return false;

    // Interprocedural calls, loads, and stores
    if (CP) {
        LocalCalls.emplace();
        IPLoads.emplace();
        IPStores.emplace();
    }

    Users.push_back(&R);
    // Walk all uses, categorize them, and ensure all are qualifying
    while (Users.size()) {
        auto *V = Users.back();
        Users.pop_back();

        // Children of the root variable at the correct offset are pushed
        // together to the front of the queue; detect when they are reached
        if (!CorrectOffset) {
            if (auto *GEP = dyn_cast<GEPOperator>(V)) {
                APInt GEPOffset(
                    DL.getPointerSizeInBits(GEP->getPointerAddressSpace()), 0);
                CorrectOffset = GEP->accumulateConstantOffset(DL, GEPOffset) &&
                                Offset->eq(GEPOffset);
            }
        }

        for (auto &U : V->uses()) {
            User *UU = U.getUser();
            Function *IF = nullptr;

            if (Instruction *I = dyn_cast<Instruction>(UU)) {
                IF = I->getFunction();

                // Skip removed or external instructions when intraprocedural
                if (Remove.count(I) || (!CP && IF != F))
                    continue;
            }

            if (auto *BCO = dyn_cast<BitCastOperator>(UU)) {
                assert(BCO->getOperand(0) == V &&
                       "Cast must be from the variable!");
                Users.push_back(BCO);
            } else if (auto *GEP = dyn_cast<GEPOperator>(UU)) {
                assert(GEP->getPointerOperand() == V &&
                       "GEP must be on the variable!");
                APInt GEPOffset(
                    DL.getPointerSizeInBits(GEP->getPointerAddressSpace()), 0);
                // Variable is equivalent to the result of the GEP
                // Note these are pushed at the front to be handled together
                if ((!Offset && resolveGEP(GEP) == V) ||
                    (Offset && GEP->accumulateConstantOffset(DL, GEPOffset) &&
                     Offset->eq(GEPOffset))) {
                    Users.push_front(GEP);
                    continue;
                } else if (!GEP->isInBounds() ||
                           !GEP->hasAllConstantIndices()) {
                    // Index is selected at runtime, may alias
                    return false;
                }

                // Access is to a different offset of the variable
                continue;
            } else if (auto *LI = dyn_cast<LoadInst>(UU)) {
                assert(LI->getPointerOperand() == V &&
                       "Load must be from the variable!");
                // Ignore loads to the parent at a different offset
                if (!CorrectOffset)
                    continue;

                // Variable must not be accessed by atomic or volatile load,
                // and load must be smaller than the store
                if (!LI->isSimple() ||
                    !(DL.getTypeStoreSize(LI->getType()) <= StoreSize))
                    return false;

                if (IF == F) {
                    assert(DT.getNode(LI->getParent()) &&
                           "Load must be in dominator tree!");

                    // Intraprocedural dominated load
                    if (DT.dominates(&S, LI))
                        Loads.push_back(LI);
                    else
                        mayCopyFrom = true;
                } else if (CP) {
                    auto IP = CP->getOnlyCallPath(F, IF);
                    if (
#if LLVM_VERSION_MAJOR >= 10
                        IP.empty()
#else
                        IP.begin() == IP.end()
#endif /* LLVM_VERSION_MAJOR */
                    ) {
                        hasMultipleCallers = true;
                        continue;
                    }
                    // Interprocedural load that will need callsite
                    // inspection
                    LocalCalls->insert(IP.begin(), IP.end());
                    IPLoads->push_back(LI);
                }
            } else if (auto *SI = dyn_cast<StoreInst>(UU)) {
                const Value *SV = SI->getValueOperand();
                // Ignore stores to the parent at a different offset
                if (!CorrectOffset) {
                    // Root variable must not escape
                    if (SV == &R)
                        return false;
                    continue;
                }

                // Variable must not be accessed by atomic or volatile store,
                // and address must not escape
                if (!SI->isSimple() || SV == V)
                    return false;

                // Value must not be thread dependent
                if (auto *C = dyn_cast<Constant>(SV))
                    if (C->isThreadDependent())
                        return false;

                if (IF == F) {
                    assert(DT.getNode(SI->getParent()) &&
                           "Store must be in dominator tree!");

                    // Intraprocedural store dominated by the store
                    if (&S != SI && DT.dominates(&S, SI))
                        ChildStores.push_back(SI);
                } else if (CP) {
                    auto IP = CP->getOnlyCallPath(F, IF);
                    if (
#if LLVM_VERSION_MAJOR >= 10
                        IP.empty()
#else
                        IP.begin() == IP.end()
#endif /* LLVM_VERSION_MAJOR */
                    ) {
                        hasMultipleCallers = true;
                        continue;
                    }
                    LocalCalls->insert(IP.begin(), IP.end());
                    // Interprocedural store that will need callsite
                    // inspection
                    IPStores->emplace_back(SI, false);
                }
            } else if (auto *CB = dyn_cast<CallBase>(UU)) {
                if (auto *II = dyn_cast<IntrinsicInst>(CB)) {
                    switch (II->getIntrinsicID()) {
                    case Intrinsic::lifetime_start:
                    case Intrinsic::lifetime_end:
                        continue;
                    // Ignore invariant.group intrinsics
                    case Intrinsic::launder_invariant_group:
                    case Intrinsic::strip_invariant_group:
                        assert(II->getArgOperand(0) == V &&
                               "Invariant group must be on the argument!");
                        Users.push_back(II);
                        continue;
                        break;
                    }
                }

                if (CB->isArgOperand(&U)) {
                    unsigned ArgNo = U.getOperandNo();
                    // Argument must not be captured
                    if (!CB->doesNotCapture(ArgNo))
                        return false;

                    if (CB->hasFnAttr(Attribute::InaccessibleMemOnly) ||
                        CB->hasFnAttr(Attribute::ReadNone) ||
                        CB->paramHasAttr(ArgNo, Attribute::ReadNone)) {
                        if (IF == F) {
                            auto *CF = CB->getCalledFunction();
                            if (CorrectOffset && CF &&
                                isCFIPointerFunction(*CF))
                                LocalMessages.push_back(CB);
                        } else
                            hasMultipleCallers = true;
                        // Operand is not accessed, ignore it
                        continue;
                    } else if (CB->hasFnAttr(Attribute::ReadOnly) ||
                               CB->paramHasAttr(ArgNo, Attribute::ReadOnly)) {
                        mayCopyFrom = true;

                        // Ignore may-reads to the parent at a potentially
                        // different offset
                        if (!CorrectOffset)
                            continue;

                        // Operand may be read, but because the size of the
                        // read is unknown, must ensure that the original
                        // object is same size as the store
                        if (DL.getTypeStoreSize(
                                R.getType()->getPointerElementType()) !=
                            StoreSize)
                            return false;

                        // Track a may load callsite by splitting the
                        // operand into a separate definition here, so that
                        // it can be subsequently replaced if optimizable
                        // FIXME: Allow this to be reverted if the load is
                        // discarded or otherwise not subsequently optimized
                        if (IF == F) {
                            assert(DT.getNode(CB->getParent()) &&
                                   "Call must be in dominator tree!");
                            if (!DT.dominates(&S, CB))
                                continue;

                            Instruction *CopyDef = getSplitDefinition(V);
                            if (CopyDef) {
                                CopyDef->insertBefore(CB);
                                CB->setArgOperand(ArgNo, CopyDef);

                                // Intraprocedural may load call
                                Loads.push_back(CopyDef);
                            }
                        } else if (CP) {
                            auto IP = CP->getOnlyCallPath(F, IF);
                            if (
#if LLVM_VERSION_MAJOR >= 10
                                IP.empty()
#else
                                IP.begin() == IP.end()
#endif /* LLVM_VERSION_MAJOR */
                            ) {
                                hasMultipleCallers = true;
                                continue;
                            }

                            Instruction *CopyDef = getSplitDefinition(V);
                            if (CopyDef) {
                                CopyDef->insertBefore(CB);
                                CB->setArgOperand(ArgNo, CopyDef);

                                // Interprocedural may load call, need
                                // callsite inspection
                                LocalCalls->insert(IP.begin(), IP.end());
                                IPLoads->push_back(CopyDef);
                            }
                        }
                    } else if (CB->hasFnAttr(Attribute::WriteOnly) ||
                               CB->paramHasAttr(ArgNo, Attribute::WriteOnly)) {
                        mayCopyTo = true;

                        // Track a may store callsite
                        if (IF == F) {
                            assert(DT.getNode(CB->getParent()) &&
                                   "Call must be in dominator tree!");
                            if (DT.dominates(&S, CB)) {
                                // Intraprocedural may store call dominated
                                // by the store
                                ChildStores.push_back(CB);
                            }
                        } else if (CP) {
                            auto IP = CP->getOnlyCallPath(F, IF);
                            if (
#if LLVM_VERSION_MAJOR >= 10
                                IP.empty()
#else
                                IP.begin() == IP.end()
#endif /* LLVM_VERSION_MAJOR */
                            ) {
                                hasMultipleCallers = true;
                                continue;
                            }
                            LocalCalls->insert(IP.begin(), IP.end());
                            // Interprocedural may store call, needs
                            // callsite inspection
                            IPStores->emplace_back(CB, false);
                        }
                    } else {
                        // Variable is used by callee
                        // TODO: Analyze callee
                        return false;
                    }
                } else if (!CB->isCallee(&U)) {
                    errs() << "Call: " << *CB << "\n";
                    report_fatal_error("analyzeDefinedStore(): Unsupported "
                                       "non-callee/operand!\n");
                }
            } else if (auto *RI = dyn_cast<ReturnInst>(UU)) {
                assert(RI->getReturnValue() == V &&
                       "Return must be of the variable!");
                // Variable escapes into calling functions
                escapesReturn = true;
            } else if (isa<PHINode>(UU) || isa<SelectInst>(UU)) {
                // Aliases with other values in subsequent uses
                return false;
            } else if (isa<ExtractElementInst>(UU) ||
                       isa<InsertElementInst>(UU) ||
                       isa<PtrToIntOperator>(UU)) {
                // TODO: Unsupported instructions (e.g. offsetof)
                return false;
            } else if (isa<ICmpInst>(UU)) {
                continue;
            } else if (isa<ConstantAggregate>(UU)) {
                // Skip ConstantAggregates created for global variables
                if (!UU->getNumUses())
                    continue;
                return false;
            } else {
                errs() << "Value: " << *UU << "\n";
                report_fatal_error(
                    "analyzeDefinedStore(): Unsupported value!\n");
            }
        }
    }

    if (CP) {
        for (auto *CB : *LocalCalls) {
            bool isStore = false;

            assert(DT.getNode(CB->getParent()) &&
                   "Call must be in dominator tree!");

            // Find local callsites for interprocedural stores by checking
            // paths on the callgraph
            auto *CF = CB->getCalledFunction();
            assert(CF && "Local call must be direct!");
            for (auto ISI = IPStores->begin(), ISE = IPStores->end();
                 ISI != ISE; ++ISI) {
                auto *SF = ISI->first->getFunction();
                if (DT.dominates(&S, CB) &&
                    (CF == SF || CP->existsOnlyPath(CF, SF))) {
                    ChildStores.push_back(CB);
                    ISI->second = true;
                    isStore = true;
                    break;
                }
            }

            // FIXME: We don't reason about relative ordering of interprocedural
            // stores and loads, so skip loads when callsite is already a store
            if (isStore)
                continue;

            // Find local callsites for interprocedural loads by checking
            // paths on the callgraph
            for (auto ILI = IPLoads->begin(); ILI != IPLoads->end();) {
                auto *LF = (*ILI)->getFunction();
                // There may be multiple callsites to the same function, so
                // remove localized interprocedural loads
                if (DT.dominates(&S, CB) &&
                    (CF == LF || CP->existsOnlyPath(CF, LF))) {
                    Loads.push_back(*ILI);
                    ILI = IPLoads->erase(ILI);
                    continue;
                }

                ++ILI;
            }
        }

        // Check if any interprocedural loads/stores failed to localize
        if (IPLoads->size() ||
            any_of(*IPStores, [](auto &P) { return !P.second; }))
            hasMultipleCallers = true;
    }

    // Remove local loads dominated by child stores
    for (auto LI = Loads.begin(); LI != Loads.end();) {
        Instruction *L = *LI;
        if (any_of(ChildStores, [&L, &DT](const Instruction *CS) {
                return DT.dominates(CS, L);
            })) {
            if (L->getFunction() != F) {
                // Unable to localize, mark multiple callers
                hasMultipleCallers = true;
            }

            LI = Loads.erase(LI);
            continue;
        }

        ++LI;
    }

    return true;
}

// Given that C1 dominates C2, check that there are no unsafe instructions on
// the path from C1 to C2. This includes calls, load/stores (for
// defines/invalidates) of the pointee, and conditional branches.
static bool isSafeMessagePath(const CallBase *C1, const CallBase *C2,
                              bool noLoad, bool noCondBr,
                              bool hasMultipleCallers,
                              const DominatorTree *DT) {
    assert(DT->dominates(C1, C2));

    const auto *P = simplify(C1->getArgOperand(0));
    auto isOk = [&](const Instruction *I) -> bool {
        if (auto *II = dyn_cast<IntrinsicInst>(I)) {
            switch (II->getIntrinsicID()) {
            case Intrinsic::dbg_addr:
            case Intrinsic::dbg_declare:
            case Intrinsic::dbg_label:
            case Intrinsic::dbg_value:
            case Intrinsic::lifetime_start:
            case Intrinsic::lifetime_end:
            case Intrinsic::launder_invariant_group:
            case Intrinsic::strip_invariant_group:
                return true;
            }

            return !hasMultipleCallers;
        } else if (isa<CallBase>(I))
            return !hasMultipleCallers;
        else if (auto *LI = dyn_cast<LoadInst>(I)) {
            if (noLoad && simplify(LI->getPointerOperand()) == P)
                return false;
        } else if (auto *SI = dyn_cast<StoreInst>(I)) {
            if (!noLoad && simplify(SI->getPointerOperand()) == P)
                return false;
        } else if (auto *BI = dyn_cast<BranchInst>(I)) {
            if (noCondBr && BI->isConditional())
                return false;
        }

        return true;
    };

    // Iterate through basic blocks/instructions between C1 and C2
    if (C1->getParent() != C2->getParent()) {
        for (auto *I = C1->getNextNode(); I; I = I->getNextNode())
            if (!isOk(I))
                return false;

        auto *N1 = DT->getNode(C1->getParent()),
             *N2 = DT->getNode(C2->getParent());
        for (auto It = N1->begin(); It != N1->end(); ++It) {
            if (DT->dominates(*It, N2)) {
                for (auto &I : *(*It)->getBlock()) {
                    if (!isOk(&I))
                        return false;
                }
            }
        }

        for (auto *I = C2->getPrevNode(); I; I = I->getPrevNode())
            if (!isOk(I))
                return false;
    } else {
        for (auto *I = C1->getNextNode(); I && I != C2; I = I->getNextNode()) {
            if (!isOk(I))
                return false;
        }
    }

    return true;
}

static bool checkProtectReturn(const Function &F) {
    if (F.hasFnAttribute(Attribute::Naked) ||
        F.hasFnAttribute(Attribute::NoReturn)) {
        outs() << F.getName()
               << ": Skipping return pointer checks for naked or noreturn "
                  "function!\n";
        return false;
    }

    bool mayWrite = !F.hasFnAttribute(Attribute::ReadNone) &&
                    !F.hasFnAttribute(Attribute::ReadOnly);
    if (mayWrite &&
        ((LTOTime && !F.hasAddressTaken() && !F.getName().equals("main")) ||
         (!LTOTime && !F.hasAvailableExternallyLinkage()))) {
        bool alwaysTailCalled = true;
        // Check if this function is always tail called
        for (auto *U : F.users()) {
            if (auto *CB = dyn_cast<CallBase>(U))
                if (!CB->isMustTailCall()) {
                    alwaysTailCalled = false;
                    break;
                }
        }

        if (alwaysTailCalled) {
            mayWrite = false;

            outs() << F.getName()
                   << ": Skipping return pointer checks for always tail called "
                      "function!\n";
        }
    }

    return mayWrite;
}

// Create recursion check on root global variable in context of given function
static unsigned createRecursionCheck(IRBuilder<> &IRB, Function &F,
                                     SmallSet<ReturnInst *, 2> *NeedGuardRI,
                                     Function *TF, Function *ARA, Function *RA,
                                     FunctionCallee &PCIF,
                                     const DominatorTree *DT,
                                     const GlobalVariable *Root) {
    auto *IntTy = IRB.getInt1Ty();
    auto *False = IRB.getFalse();
    // Lookup/create the recursion guard for this GlobalVariable
    auto *M = F.getParent();
    auto Name = Root->getName().str() + "_guard";
    auto *Guard = M->getGlobalVariable(Name);
    if (!Guard) {
        Guard = new GlobalVariable(*M, IntTy, false,
                                   GlobalVariable::InternalLinkage, False, Name,
                                   const_cast<GlobalVariable *>(Root));
    }

    // Get insertion point in the entry block, while skipping AllocaInst
    auto *InsertPt = getFirstNonAllocaInsertionPt(F.getEntryBlock());
    assert(InsertPt && "Insertion point must be non-NULL!");
    IRB.SetInsertPoint(InsertPt);

    // Create the check, set, and split the block before the increment
    auto *ELI = IRB.CreateLoad(IntTy, Guard);
    auto *ESI = IRB.CreateStore(IRB.getTrue(), Guard);
    auto *NewBBTI = SplitBlockAndInsertIfThen(ELI, ESI, true);

    // Add the trap to the new block
    IRB.SetInsertPoint(NewBBTI);
    IRB.CreateCall(TF);

    // Walk the function and identify all exit blocks, for a single exit
    // block Based on UnifyFunctionExitNodes
    SmallSet<ReturnInst *, 8> ReturnInsts;
    for (BasicBlock &BB : F) {
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            ReturnInsts.insert(RI);
    }

    // Create a unified exit block
    ReturnInst *RI;
    PHINode *ExitPHI = nullptr;
    auto *RetTy = F.getReturnType();
    auto *Exit = BasicBlock::Create(IRB.getContext(), "GuardExitBB", &F);

    IRB.SetInsertPoint(Exit);
    if (!RetTy->isVoidTy()) {
        ExitPHI = IRB.CreatePHI(RetTy, ReturnInsts.size(), "GuardExitPHI");
        RI = IRB.CreateRet(ExitPHI);
    } else
        RI = IRB.CreateRetVoid();
    if (NeedGuardRI)
        NeedGuardRI->insert(RI);

    // Redirect all previous exits to the unified exit
    for (ReturnInst *RI : ReturnInsts) {
        if (ExitPHI)
            ExitPHI->addIncoming(RI->getOperand(0), RI->getParent());
        IRB.SetInsertPoint(RI);
        IRB.CreateBr(Exit);

        if (NeedGuardRI)
            NeedGuardRI->erase(RI);
        RI->eraseFromParent();
    }

    // Create the set in the exit
    IRB.SetInsertPoint(getFirstNonAllocaInsertionPt(*Exit));
    IRB.CreateStore(False, Guard);
    return 1;
}

/* Visitor for modifying instructions */
struct FinalizeVisitor : public InstVisitor<FinalizeVisitor> {
    IRBuilder<> IRB;
    CallPaths *CP;
    DominatorCallback &DCB;
    Function *TF, *ARA, *RA, *FF, *RF;
    FunctionCallee PCF, PDF, PCIF, PIF, PMCF, PMMF, PFF, PRF;

    /* Information about current module */
    bool hasGlobals, hasChecks, hasDefines;

    /* Information about current function */
    Function *currentFunc;
    DominatorTree *DT;
    bool shouldProtectReturn;

    // List of per-function dominated loads and message calls
    SmallVector<Instruction *, 4> DominatedLoads;
    SmallVector<CallBase *, 4> LocalMessages;
    // Set of per-function GVs that need guards
    SmallSet<const GlobalVariable *, 2> NeedGuardGV;
    // Set of per-function RIs that need check-invalidates
    SmallSet<ReturnInst *, 2> NeedCheckInvRI;
    // Map of per-function pointers to their invalidation sites
    std::unordered_map<const Value *, SmallSet<const CallBase *, 2>>
        InvalidatedObjs;

    // List of per-function instructions to erase
    SmallSet<Instruction *, 1> Remove;

    FinalizeVisitor(LLVMContext &C, CallPaths *P, DominatorCallback &_DCB,
                    bool Globals)
        : IRB(C), CP(P), DCB(_DCB), hasGlobals(Globals) {}

    bool visit(Module &M) {
        visitModule(M);
        InstVisitor::visit(M.begin(), M.end());
        return hasChecks;
    }

    // Override hierarchy to perform post-visit modifications
    void visit(Function &F) {
        // If inlining is enabled, don't instrument ourselves
        if (F.isDeclaration() || isHQFunction(F))
            return;

        visitFunction(F);
        InstVisitor::visit(F.begin(), F.end());

        // Insert guards for each potentially recursive function
        for (auto *GV : NeedGuardGV) {
            LLVM_DEBUG(dbgs() << currentFunc->getName()
                              << ": Inserting recursion check on '"
                              << GV->getName() << "'!\n");
            NumRecGuards += createRecursionCheck(
                IRB, *currentFunc,
                shouldProtectReturn ? &NeedCheckInvRI : nullptr, TF, ARA, RA,
                PCIF, DT, GV);
        }
        NeedGuardGV.clear();

        // Insert define on entry and check-invalidates on each return
        if (shouldProtectReturn) {
            IRB.SetInsertPoint(
                getFirstNonAllocaInsertionPt(currentFunc->getEntryBlock()));
            Value *Args[] = {IRB.CreateCall(ARA),
                             IRB.CreateCall(RA, IRB.getInt32(0))};
            createCastedCall(IRB, PDF, Args);
            ++NumRetDefs;

            for (auto *RI : NeedCheckInvRI) {
                LLVM_DEBUG(dbgs() << currentFunc->getName()
                                  << ": Inserting return pointer check!\n");
                IRB.SetInsertPoint(RI);
                Value *Args[] = {IRB.CreateCall(ARA),
                                 IRB.CreateCall(RA, IRB.getInt32(0))};
                createCastedCall(IRB, PCIF, Args);
                ++NumRetChks;
            }
        }
        NeedCheckInvRI.clear();

        for (auto *R : Remove) {
            // Need a new terminator instruction for the basic block
            if (auto *II = dyn_cast<InvokeInst>(R)) {
                IRB.SetInsertPoint(II);
                IRB.CreateBr(II->getNormalDest());
                II->getUnwindDest()->removePredecessor(II->getParent());
            }

            R->eraseFromParent();
        }
        Remove.clear();
    }

    void visit(BasicBlock &BB) {
        visitBasicBlock(BB);
        InstVisitor::visit(BB.begin(), BB.end());
    }

    void visit(Instruction &I) {
        if (Remove.count(&I))
            return;

        visitInstruction(I);
        InstVisitor::visit(I);
    }

    void visitModule(Module &M) {
        LLVMContext &C = M.getContext();

        TF = Intrinsic::getDeclaration(&M, Intrinsic::trap);
        if (RunCFIRetAddr) {
            PointerType *PTy = Type::getInt8PtrTy(C);
            ARA = Intrinsic::getDeclaration(
                &M, Intrinsic::addressofreturnaddress, PTy);
            RA = Intrinsic::getDeclaration(&M, Intrinsic::returnaddress);
        }

        createHQFunctions(IRB, M, &PCF, &PCIF, &PDF, &PIF, nullptr, &PMCF,
                          &PMMF, &PFF, &PRF);

        if (RunCFI && RedirectFunctions) {
            FF = M.getFunction("free");
            RF = M.getFunction("realloc");
        }

        hasChecks = LTOTime && (cast<Function>(PCF.getCallee())
                                    ->hasFnAttribute(Attribute::AlwaysInline) ||
                                cast<Function>(PCF.getCallee())->getNumUses());
        hasDefines =
            LTOTime && (cast<Function>(PDF.getCallee())
                            ->hasFnAttribute(Attribute::AlwaysInline) ||
                        PDF.getCallee()->getNumUses());
    }

    void visitFunction(Function &F) {
        currentFunc = &F;
        DT = nullptr;
        shouldProtectReturn = RunCFIRetAddr ? checkProtectReturn(F) : false;

        InvalidatedObjs.clear();
    }

    void visitCallBase(CallBase &CB) {
        if (!RunCFI)
            return;

        Function *CF = CB.getCalledFunction();

        if (!CF)
            return;
        else if (CF == PDF.getCallee()) {
            // Remove define if there are no checked pointers
            if (!hasChecks) {
                Remove.insert(&CB);
                ++NumOptDef;
                return;
            }

            bool hasMultipleStores = false;
            Value *A0 = const_cast<Value *>(simplify(CB.getArgOperand(0))),
                  *A1 = const_cast<Value *>(simplify(CB.getArgOperand(1)));
            StoreInst *SI = getInstrumentedStore(CB, A0, A1, hasMultipleStores);
            if (!SI) {
                // May have already been removed by changes to global
                // variable optimizer and memory to register promotion
                LLVM_DEBUG(dbgs() << currentFunc->getName()
                                  << ": Eliding defined pointer '"
                                  << A0->getName() << "' without store!\n");
                Remove.insert(&CB);
                ++NumOptDef;
                return;
            } else if (hasMultipleStores ||
                       currentFunc->callsFunctionThatReturnsTwice())
                return;

            // Get the root variable
            auto *Root =
                const_cast<Value *>(getRootVariable(SI->getPointerOperand()));
            if (!Root)
                return;

            auto *Parent = Root;
            const DataLayout &DL = currentFunc->getParent()->getDataLayout();
            APInt Offset(DL.getPointerSizeInBits(
                             Root->getType()->getPointerAddressSpace()),
                         0);
            // Root variable is a subfield, obtain its offset
            if (auto *GEP = dyn_cast<GEPOperator>(Root)) {
                if (!GEP->accumulateConstantOffset(DL, Offset))
                    return;
                Parent = const_cast<Value *>(
                    simplify(Root->stripInBoundsConstantOffsets(), false));
            }

            // Fetch the dominator tree
            if (!DT)
                DT = DCB(*currentFunc);
            assert(DT && "Missing dominator tree!");

            bool hasMultipleCallers = false, mayEscape = false,
                 mayCopyFrom = false, mayCopyTo = false;
            // Analyze subsequent loads/messages involving the store/define
            if (!analyzeDefinedStore(
                    DL, *DT, CP, DominatedLoads, LocalMessages, mayEscape,
                    hasMultipleCallers, mayCopyFrom, mayCopyTo, *Parent, *SI,
                    isa<GEPOperator>(Root) ? &Offset : nullptr, Remove)) {
                DominatedLoads.clear();
                LocalMessages.clear();
                return;
            }

            assert(isEquivalent(SI->getValueOperand(), A1) &&
                   "Store and define should have equivalent value!");

            // Skip message analysis if there exists other copies/stores
            // FIXME: Need to localize and push into list of messages
            if (mayCopyTo)
                LocalMessages.clear();

            // Remove duplicate stores/invalidates, or all if no checks
            // FIXME: Postdominators would be more straightforward, but
            // exception handlers add additional non-dominated exit blocks.
            if (LocalMessages.size()) {
                CallBase *LatestDefine = nullptr, *EarliestInvalidate = nullptr,
                         *Check = nullptr;
                bool hasPathChecks = false;

                // Find checks, compute the latest dominated define, and the
                // earliest dominating invalidate
                for (auto *M : LocalMessages) {
                    const auto *MC = M->getCalledFunction();

                    if (MC == PCF.getCallee()) {
                        Check = hasPathChecks ? nullptr : M;
                        hasPathChecks = true;
                    } else if (MC == PDF.getCallee()) {
                        // Later define, no conditional branches, and value is
                        // not observed
                        if (!LatestDefine ||
                            (DT->dominates(LatestDefine, M) &&
                             isSafeMessagePath(LatestDefine, M, true, true,
                                               hasMultipleCallers, DT)))
                            LatestDefine = M;
                    } else if (MC == PIF.getCallee()) {
                        // Earlier invalidate, and value is not overwritten
                        if (!EarliestInvalidate ||
                            (DT->dominates(M, EarliestInvalidate) &&
                             isSafeMessagePath(M, EarliestInvalidate, false,
                                               false, hasMultipleCallers, DT)))
                            EarliestInvalidate = M;
                    } else if (MC != PCIF.getCallee())
                        report_fatal_error("Unrecognized call!");
                }

                // All messages can be removed if there are no checks, and
                // either the pointer doesn't escape and isn't intraprocedural,
                // or the latest define dominates the earliest invalidate and
                // the value is not observed
                const bool RemoveAll =
                    !hasPathChecks && !mayCopyFrom &&
                    ((!isa<Argument>(Parent) && !mayEscape &&
                      !hasMultipleCallers) ||
                     (LatestDefine && EarliestInvalidate &&
                      DT->dominates(LatestDefine, EarliestInvalidate) &&
                      isSafeMessagePath(LatestDefine, EarliestInvalidate, true,
                                        false, hasMultipleCallers, DT)));
                if (RemoveAll)
                    Check = nullptr;

                for (auto *M : LocalMessages) {
                    const auto *MC = M->getCalledFunction();
                    // Remove a message if (1) all messages are removable, (2)
                    // it is a define and dominates the latest define without
                    // conditional branches, (3) it is an invalidate and is
                    // dominated by the earliest invalidate, or (3) it is a
                    // check and is dominated by latest define with the value
                    // never being overwritten
                    if (RemoveAll ||
                        (MC == PDF.getCallee() && LatestDefine &&
                         DT->dominates(M, LatestDefine) &&
                         isSafeMessagePath(M, LatestDefine, true, true,
                                           hasMultipleCallers, DT)) ||
                        (MC == PIF.getCallee() && EarliestInvalidate &&
                         DT->dominates(EarliestInvalidate, M)) ||
                        (MC == PCF.getCallee() && LatestDefine &&
                         DT->dominates(LatestDefine, M) &&
                         isSafeMessagePath(LatestDefine, M, false, true,
                                           hasMultipleCallers, DT))) {
                        if (MC == PCF.getCallee() || MC == PCIF.getCallee())
                            ++NumOptChk;
                        else if (MC == PDF.getCallee())
                            ++NumOptDef;
                        else if (MC == PIF.getCallee() ||
                                 MC == PCIF.getCallee())
                            ++NumOptInv;
                        Remove.insert(M);
                    }
                }

                // If there is only one check, and it dominates the invalidate,
                // replace both with a combined check-invalidate message
                if (Check && EarliestInvalidate &&
                    DT->dominates(Check, EarliestInvalidate)) {
                    Check->setCalledFunction(PCIF);
                    Remove.insert(EarliestInvalidate);
                    ++NumChkInv;
                }

                LocalMessages.clear();
            }

            // Elide subsequent loads/checks dominated by the pointer store
            if (!mayEscape && DominatedLoads.size()) {
                // If the underlying variable is a static global, and it is
                // accessed by multiple functions or a unique function that may
                // be recursive, it is difficult to determine statically if
                // simultaneous accesses may occur, because of indirect calls on
                // the call graph. As a workaround, we use a runtime check to
                // guard elided loads.
                GlobalVariable *GV = dyn_cast<GlobalVariable>(Root);
                if (GV &&
                    (hasMultipleCallers || !currentFunc->doesNotRecurse()))
                    NeedGuardGV.insert(GV);

                Value *ReplaceV = A1;
                // Check for invariant group metadata, and strip if present
                if (auto *I = dyn_cast<Instruction>(ReplaceV)) {
                    if (I->hasMetadata(LLVMContext::MD_invariant_group)) {
                        IRB.SetInsertPoint(CB.getNextNode());
                        ReplaceV = IRB.CreateStripInvariantGroup(I);
                    }
                }

                // Replace dominated loads
                std::unordered_map<
                    std::pair<const GlobalVariable *, const Function *>,
                    Instruction *>
                    HoistedLoads;
                for (auto *L : DominatedLoads) {
                    Value *NewV = ReplaceV;

                    // Get replacement for interprocedural loads of GV
                    // TODO: Pass value through intermediary calls as argument?
                    if (L->getFunction() != currentFunc) {
                        assert(GV && "Interprocedural load must be of GV!");
                        NewV = getIPReplacement(IRB, GV, L, PCF, HoistedLoads);
                        // This is the canonical replacement, skip it
                        if (!NewV)
                            continue;
                    }

                    LLVM_DEBUG(dbgs() << currentFunc->getName()
                                      << ": Eliding dominated load of '"
                                      << Root->getName() << "'!\n");

                    // Add cast, if necessary, and replace all uses
                    // Relies on DCE to remove dead bitcasts
                    if (Constant *C = dyn_cast<Constant>(NewV))
                        NewV = ConstantExpr::getPointerCast(C, L->getType());
                    else if (L->getType() != NewV->getType()) {
                        IRB.SetInsertPoint(L);
                        NewV = IRB.CreatePointerCast(NewV, L->getType());
                    }

                    assert(!isa<Instruction>(NewV) ||
                           L->getFunction() ==
                               cast<Instruction>(NewV)->getFunction());

                    // Remove all checks on L, and replace remaining uses with
                    // its replacement
                    removeAllChecks(L, *cast<Function>(PCF.getCallee()),
                                    Remove);
                    L->replaceAllUsesWith(NewV);
                    Remove.insert(L);
                }

                DominatedLoads.clear();
            }
        } else if (CF == PCF.getCallee()) {
            Value *A0 = CB.getArgOperand(0),
                  *A1 = const_cast<Value *>(simplify(CB.getArgOperand(1)));

            // Remove check if there are no defined pointers, or if it is a
            // removable check
            if ((!hasGlobals && !hasDefines) ||
                isRemovableCheck(*A0, *A1, *cast<Function>(PCF.getCallee()),
                                 Remove)) {
                Remove.insert(&CB);
                ++NumOptChk;
            }
        } else if (CF == PIF.getCallee()) {
            // Fetch the dominator tree
            if (!DT)
                DT = DCB(*currentFunc);
            assert(DT && "Missing dominator tree!");

            // Remove invalidate if there are no defined or checked pointers,
            // or if it is a removable invalidate
            if ((!hasGlobals && !hasDefines) || !hasChecks ||
                isRemovableInvalidate(CB, *cast<Function>(PDF.getCallee()), DT,
                                      InvalidatedObjs, Remove)) {
                Remove.insert(&CB);
                ++NumOptInv;
            } else {
                auto *V = const_cast<Value *>(simplify(CB.getArgOperand(0)));
                auto It = InvalidatedObjs.find(V);
                if (It == InvalidatedObjs.end())
                    It = InvalidatedObjs
                             .emplace(V, SmallSet<const CallBase *, 2>())
                             .first;
                It->second.insert(&CB);
            }
        } else if (CF == FF || CF == RF) {
            if (RedirectFunctions && (hasGlobals || hasDefines) &&
                isFunctionPointer(*CB.getArgOperand(0), UseStrictFP, true)) {
                auto &NewDst = CF == FF ? PFF : PRF;
                assert(CB.getFunctionType() == NewDst.getFunctionType());
                CB.setCalledFunction(NewDst);
                ++NumFree;
            }
        }
    }

    void visitIntrinsicInst(IntrinsicInst &II) {
        if (!RunCFI)
            return;

        const auto IID = II.getIntrinsicID();
        switch (IID) {
        case Intrinsic::memcpy:
        case Intrinsic::memmove: {
            Value *A0 =
                      const_cast<Value *>(simplify(II.getArgOperand(0), false)),
                  *A1 =
                      const_cast<Value *>(simplify(II.getArgOperand(1), false)),
                  *A2 = II.getArgOperand(2);

            if ((hasGlobals || hasDefines) && !isCString(*A1) &&
                (isFunctionPointer(*A0, UseStrictFP, true) ||
                 isFunctionPointer(*A1, UseStrictFP, true))) {
                // Different number of arguments, recreate the call
                IRB.SetInsertPoint(II.getNextNode());
                Value *Args[] = {A0, A1, A2};
                createCastedCall(IRB, IID == Intrinsic::memcpy ? PMCF : PMMF,
                                 Args);
                ++NumCopyMove;
            }
        } break;
        default:
            break;
        }
    }

    void visitReturnInst(ReturnInst &RI) {
        if (shouldProtectReturn)
            NeedCheckInvRI.insert(&RI);
    }
};

static bool finalizeCFIInstrumentation(Module &M, CallGraph *CG,
                                       DominatorCallback DCB) {
    if (!RunCFI && !RunCFIRetAddr)
        return false;

    LLVMContext &C = M.getContext();
    IRBuilder<> IRB(C);
    Optional<CallPaths> CP;
    bool Changed = false;

    // Instrument global variables
    StructType *STy = nullptr;
    SmallVector<Constant *, 8> InitGlobalsInternal, InitGlobalsExternal;
    if (RunCFI) {
        PointerType *PTy = Type::getInt8PtrTy(C);
        PointerType *PPTy = PointerType::getUnqual(PTy);
        STy = StructType::get(C, {PPTy, PTy});
        // Fetch C++ virtual error handlers
        const Function *PureVirt =
            SkipCXXVirtualError ? M.getFunction(getPureVirtualName()) : nullptr;
        const Function *DelVirt = SkipCXXVirtualError
                                      ? M.getFunction(getDeletedVirtualName())
                                      : nullptr;
        instrumentGlobalVariables(M, *STy, LTOTime, {PureVirt, DelVirt},
                                  InitGlobalsInternal, InitGlobalsExternal);
    }
    const bool hasGlobals =
        InitGlobalsInternal.size() || InitGlobalsExternal.size();

    if (UseCallGraphAnalysis && CG)
        CP.emplace(*CG);
    FinalizeVisitor FV(C, CP ? CP.getPointer() : nullptr, DCB, hasGlobals);

    // Perform visit and add initialization function if checks exist
    if (FV.visit(M) && hasGlobals && RunCFI) {
        createGlobalInit(M, InitGlobalsInternal, InitGlobalsExternal);
        NumIntGlobal += InitGlobalsInternal.size();
        NumExtGlobal += InitGlobalsExternal.size();

        for (auto *C : InitGlobalsInternal) {
            if (isFunctionPointerTy(*C->getType()))
                ++NumFPGlobal;
            else
                ++NumVTGlobal;
        }

        for (auto *C : InitGlobalsExternal) {
            if (isFunctionPointerTy(*C->getType()))
                ++NumFPGlobal;
            else
                ++NumVTGlobal;
        }
    } else {
        for (Constant *C : InitGlobalsInternal)
            C->destroyConstant();
        InitGlobalsInternal.clear();

        for (Constant *C : InitGlobalsExternal)
            C->destroyConstant();
        InitGlobalsExternal.clear();
    }

    Changed |= NumOptDef || NumOptChk || NumChkInv || NumOptInv ||
               NumCopyMove || NumFree || NumRecGuards || NumVTGlobal ||
               NumFPGlobal || NumRetChks || NumRetDefs;
    if (Changed) {
        outs() << M.getName() << ": Finalized ";
        if (RunCFI)
            outs() << "away pointers (" << NumOptDef << " defines, "
                   << NumOptChk << " checks, " << NumChkInv
                   << " check-invalidates, " << NumOptInv
                   << " invalidates), instrumented globals (" << NumRecGuards
                   << " recursion guards, " << NumFPGlobal
                   << " function pointers, " << NumVTGlobal
                   << " vtable pointers | " << NumIntGlobal << " internal, "
                   << NumExtGlobal << " external); ";
        if (NumCopyMove || (RedirectFunctions && NumFree))
            outs() << "redirected calls (" << NumCopyMove << " copies/moves, "
                   << NumFree << " frees); ";
        if (RunCFIRetAddr && (NumRetDefs || NumRetChks))
            outs() << "return pointers (" << NumRetDefs << " defines, "
                   << NumRetChks << " checks-invalidates)";
        outs() << "\n";
    }

    Changed |= performInlining(M, InlinePath);
    return Changed;
}

/* Implementation for legacy pass manager */
void CFIFinalizeLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
    if (UseCallGraphAnalysis)
        AU.addRequired<CallGraphWrapperPass>();
    if (CFIDominatorAnalysis)
        AU.addRequired<DominatorTreeWrapperPass>();
}

bool CFIFinalizeLegacyPass::runOnModule(Module &M) {
    auto *CG = UseCallGraphAnalysis
                   ? &this->getAnalysis<CallGraphWrapperPass>().getCallGraph()
                   : nullptr;
    auto DTCallback = [this](Function &F) -> DominatorTree * {
        return CFIDominatorAnalysis && !F.isDeclaration()
                   ? &this->getAnalysis<DominatorTreeWrapperPass>(F)
                          .getDomTree()
                   : nullptr;
    };

    return finalizeCFIInstrumentation(M, CG, DTCallback);
}

char CFIFinalizeLegacyPass::ID = 0;

// Use this because RegisterPass<...>(...) does not support dependent passes
INITIALIZE_PASS_BEGIN(CFIFinalizeLegacyPass, DEBUG_TYPE,
                      "CFI Finalization Pass", false, false)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(CFIFinalizeLegacyPass, DEBUG_TYPE, "CFI Finalization Pass",
                    false, false)

static void RegisterLegacyPasses(const PassManagerBuilder &Builder,
                                 legacy::PassManagerBase &PM) {
    bool Inline = !InlinePath.empty() || getInlinePath();
    PassRegistry *PR = PassRegistry::getPassRegistry();

    initializeCFIFinalizeLegacyPassPass(*PR);
    PM.add(new CFIFinalizeLegacyPass());
#ifndef NDEBUG
    PM.add(createVerifierPass());
#endif /* NDEBUG */
    if (Inline)
        PM.add(createAlwaysInlinerLegacyPass());
    PM.add(createDeadCodeEliminationPass());
    PM.add(createCFGSimplificationPass());
    if (Inline)
        PM.add(createGlobalDCEPass());
}

static RegisterStandardPasses CFIFinalizeRegisterLast(
    PassManagerBuilder::EP_OptimizerLast,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        if (!LTOTime)
            RegisterLegacyPasses(Builder, PM);
    });

static RegisterStandardPasses CFIFinalizeRegisterL0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        if (!LTOTime)
            RegisterLegacyPasses(Builder, PM);
    });

static RegisterStandardPasses CFIFinalizeRegisterLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        if (LTOTime)
            RegisterLegacyPasses(Builder, PM);
    });

/* Implementation for new pass manager */
void CFIFinalizePass::create(ModulePassManager &MPM) {
    bool Inline = !InlinePath.empty() || getInlinePath();

    if (UseCallGraphAnalysis)
        MPM.addPass(RequireAnalysisPass<CallGraphAnalysis, Module>());
    if (CFIDominatorAnalysis)
        MPM.addPass(RequireAnalysisPass<DominatorTreeAnalysis, Module>());
    MPM.addPass(CFIFinalizePass());
#ifndef NDEBUG
    MPM.addPass(VerifierPass());
#endif /* NDEBUG */
    if (Inline)
        MPM.addPass(AlwaysInlinerPass());

    FunctionPassManager FPM;
    FPM.addPass(DCEPass());
    FPM.addPass(SimplifyCFGPass());
    MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

    if (Inline)
        MPM.addPass(GlobalDCEPass());
}

PreservedAnalyses CFIFinalizePass::run(Module &M, ModuleAnalysisManager &MAM) {
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    auto *CG =
        UseCallGraphAnalysis ? &MAM.getResult<CallGraphAnalysis>(M) : nullptr;
    auto DTCallback = [&FAM](Function &F) -> DominatorTree * {
        return CFIDominatorAnalysis && !F.isDeclaration()
                   ? &FAM.getResult<DominatorTreeAnalysis>(F)
                   : nullptr;
    };

    if (!finalizeCFIInstrumentation(M, CG, DTCallback))
        return PreservedAnalyses::all();

    PreservedAnalyses PA = PreservedAnalyses::none();
    if (!CFIDominatorAnalysis)
        PA.preserve<LoopAnalysis>();
    return PA;
}

#undef DEBUG_TYPE
