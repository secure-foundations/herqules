#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Scalar.h"

#ifndef NDEBUG
#include "llvm/IR/Verifier.h"
#endif

#include <queue>
#include <unordered_map>

#include "config.h"

#include "cfi-init.h"
#include "cfi-instrument.h"
#include "utils.h"

#define DEBUG_TYPE "cfi-instrument"

// First LLVM pass that converts type tests to our CFI checks before the
// built-in LowerTypeTests pass. It shouldn't run too late, because other
// optimization passes may interfere with our analysis, so run it at
// EP_ModuleOptimizerEarly. One downside of this is that optimizations which may
// allow check elision won't run until later, so those need to be removed by the
// subsequent CFIFinalize pass. This is also why redirection of builtin memory
// functions is delayed until that pass, because e.g. function inlining and
// argument promotion can eliminate some memory copies.
// When the WholeProgramDevirt pass is enabled, we need to run this pass again
// immediately afterwards, to handle any new type tests intrinsics introduced
// from non-devirtualizable checked loads.

using namespace llvm;

static cl::opt<bool> SPECOverrides(
    "cfi-spec-overrides",
    cl::desc("Use built-in overrides for function attributes and strict "
             "function pointer subtypes in SPEC benchmarks (default = true)"),
    cl::init(true));

// Ensure statistics are defined even in release mode
#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
STATISTIC(NumVTDef, "Number of instrumented object definitions");
STATISTIC(NumVTInv, "Number of instrumented object invalidations");
STATISTIC(NumFPDef, "Number of instrumented function pointer definitions");
STATISTIC(NumFPInv, "Number of instrumented function pointer invalidations");
STATISTIC(NumChk, "Number of instrumented pointer checks");
STATISTIC(NumOptChk, "Number of pointer checks optimized away");
STATISTIC(NumFnAttr, "Number of applied memory function attributes");
STATISTIC(NumEarlyLib, "Number of early functions instrumented/redirected");
#else
static unsigned int NumVTDef = 0, NumVTInv = 0, NumFPDef = 0, NumFPInv = 0,
                    NumChk = 0, NumOptChk = 0, NumFnAttr = 0, NumEarlyLib = 0;
#endif /* !NDEBUG || LLVM_ENABLE_STATS */

/* Types */
using DTCallback = function_ref<const DominatorTree *(Function &F)>;

/* Type tests */

// Given a type test intrinsic, find the subsequent checked call
// FIXME: Brittle basic block matching
static CallBase *getCheckedCall(IntrinsicInst &II) {
    std::queue<BasicBlock *> Queue;
    SmallSet<const BasicBlock *, 4> Visited;

    for (BasicBlock *BB : successors(II.getParent()))
        Queue.push(BB);

    while (!Queue.empty()) {
        BasicBlock *BB = Queue.front();
        Queue.pop();

        // Skip blocks where the type test fails
        if (BB->getName().startswith("trap"))
            continue;

        for (auto I = BB->begin(), E = BB->end(); I != E; ++I) {
            if (auto *NI = dyn_cast<IntrinsicInst>(I)) {
                // Avoid overlapping with another type test
                if (NI->getIntrinsicID() == Intrinsic::type_test)
                    break;
            } else if (auto *CB = dyn_cast<CallBase>(I))
                return CB;
            else if (auto *BI = dyn_cast<BranchInst>(I)) {
                // Search through successors
                for (unsigned i = 0; i < BI->getNumSuccessors(); ++i) {
                    BasicBlock *Succ = BI->getSuccessor(i);
                    if (!Visited.count(Succ)) {
                        Visited.insert(BB);
                        Queue.push(Succ);
                    }
                }
            }
        }
    }

    return nullptr;
}

/* Helper functions */
// Given a checked call, determine if it can be optimized out
static Value *optimizeCheckedCall(CallBase &CB) {
    Value *V = const_cast<Value *>(simplify(CB.getCalledOperand()));

    // Direct function call
    if (auto *F = dyn_cast<Function>(V))
        return F;
    else if (auto *LI = dyn_cast<LoadInst>(V))
        return dyn_cast<Function>(
            const_cast<Value *>(simplify(LI->getPointerOperand())));

    return nullptr;
}

// Returns true if the value V can be a constant address
static inline bool isConstantAddress(Value *V) {
    return isa<Argument>(V) || isa<CallBase>(V) || isa<ConstantInt>(V) ||
           isa<ConstantPointerNull>(V) || isa<GlobalAlias>(V) ||
           isa<GlobalObject>(V) || isa<UndefValue>(V);
}

// Get pointer and value from a given instruction, iterating backwards
static std::pair<Value *, Value *> getPtrAndVal(Value *V) {
    // Ends up in one of five cases:
    // (1): Can retrieve both pointer and value (Store, Load)
    // (2): Can only retrieve pointer (Alloca, ExtractValue, unresolved GEP)
    // (3): Strip off cast and recurse (Cast, ConstantExpr)
    // (4): Can only retrieve value (isConstantAddress, IntToPtr)
    // (5): Need to recurse on multiple values, unsupported (PHINode, Select)
    while (V) {
        if (auto *LI = dyn_cast<LoadInst>(V)) {
            // FIXME: Pass-by-value aggregate types may be copied by
            // function inlining, or promoted into scalarized arguments
            // by argument promotion, at O3. Disable inlining and hide the
            // byval attribute to prevent this behavior.
            Argument *Arg = dyn_cast<Argument>(const_cast<Value *>(simplify(
                LI->getPointerOperand()->stripInBoundsConstantOffsets())));
            if (Arg && Arg->hasByValAttr() &&
                isStructPointerTy(*Arg->getType())) {
                Function *F = Arg->getParent();
                if (!F->hasFnAttribute(Attribute::NoInline))
                    F->addFnAttr(Attribute::NoInline);
                Arg->removeAttr(Attribute::ByVal);

                for (User *U : F->users())
                    if (CallBase *CB = dyn_cast<CallBase>(U))
                        CB->removeParamAttr(Arg->getArgNo(), Attribute::ByVal);
            }

            V = LI->getPointerOperand();
            return std::make_pair<>(V, LI);
        } else if (auto *SI = dyn_cast<StoreInst>(V)) {
            V = SI->getValueOperand();
            return std::make_pair<>(SI->getPointerOperand(), V);
        } else if (isa<AllocaInst>(V) || isa<ExtractValueInst>(V) ||
                   isa<IntToPtrInst>(V)) {
            // Return when it is solely a pointer
            return std::make_pair<>(V, nullptr);
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            // Resolve constant GEPs to the destination Value
            if ((V = const_cast<Value *>(resolveGEP(GEP))))
                continue;
            return std::make_pair<>(GEP, nullptr);
        } else if (auto *CI = dyn_cast<CastInst>(V)) {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            if (auto *ASCI = dyn_cast<AddrSpaceCastInst>(CI)) {
                if (ASCI->getSrcAddressSpace() == PID_ADDR_SPACE ||
                    ASCI->getDestAddressSpace() == PID_ADDR_SPACE) {
                    errs() << *ASCI << "\n";
                    report_fatal_error(
                        "getPtrAndVal(): Address space cast not allowed!");
                }
            }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            V = CI->getOperand(0);
            continue;
        } else if (auto *CE = dyn_cast<ConstantExpr>(V)) {
            if (CE->isCast()) {
                V = CE->getOperand(0);
                continue;
            }

            errs() << *CE << "\n";
            report_fatal_error("getPtrAndVal(): Unsupported ConstantExpr!");
        } else if (isConstantAddress(V) || isa<PHINode>(V) ||
                   isa<SelectInst>(V)) {
            // Return when it is solely a value, or must be handled by
            // caller (PHINode, SelectInst)
            break;
        }

        errs() << *V << "\n";
        report_fatal_error("getPtrAndVal(): Unsupported instruction!");
    }

    return std::make_pair<>(nullptr, V);
}

// Find uses of a pointer that load its value, iterating forwards
static void findValFromPtr(Value &Val, SmallVectorImpl<Instruction *> &Uses) {
    SmallVector<Value *, 4> Worklist;

    Worklist.push_back(&Val);
    while (Worklist.size()) {
        Value *V = Worklist.pop_back_val();

        if (auto *LI = dyn_cast<LoadInst>(V)) {
            // Found the load instruction
            Uses.emplace_back(LI);
            continue;
        } else if (auto *II = dyn_cast<IntrinsicInst>(V)) {
            // Reached the type test, stop searching this path
            if (II->getIntrinsicID() == Intrinsic::type_test)
                continue;
        } else if (isa<CastInst>(V) || isa<GetElementPtrInst>(V)) {
#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
            if (auto *ASCI = dyn_cast<AddrSpaceCastInst>(V)) {
                if (ASCI->getSrcAddressSpace() == PID_ADDR_SPACE ||
                    ASCI->getDestAddressSpace() == PID_ADDR_SPACE) {
                    errs() << *ASCI << "\n";
                    report_fatal_error(
                        "findValFromPtr(): Address space cast not allowed!");
                }
            }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */
            // Recurse on casts and the initial GEP
            for (User *U : V->users())
                Worklist.push_back(U);
        } else {
            errs() << *V << "\n";
            report_fatal_error("findValFromPtr(): Unsupported instruction!");
        }
    }
}

// Determine if an instruction is a vtable pointer, either direct or loaded from
// a vtable table
// FIXME: Brittle, relies on Clang CodeGen producing GEPConstExpr (vtable) or
// LoadInst (vtable table/VTT)
static bool isVTablePointer(const Value &I) {
    DedupVector<const Value *, 4> Stack;

    Stack.push_back(&I);
    while (!Stack.empty()) {
        const Value *V = Stack.pop_back_val();

        if (auto *GV = dyn_cast<GlobalVariable>(V)) {
            // Direct reference to vtable
            const Optional<std::string> Name = getDemangledName(GV->getName());
            if (Name && isVTable(*Name) && isStructPointerTy(*V->getType()))
                return true;
        } else if (auto *LI = dyn_cast<LoadInst>(V)) {
            // Loaded from vtable table (multiple inheritance)
            if (isVTableTableVariable(*simplify(
                    LI->getPointerOperand()->stripInBoundsConstantOffsets())) &&
                isIntegerPointerTy(*V->getType()))
                return true;
        } else if (auto *BCO = dyn_cast<BitCastOperator>(V)) {
            Stack.push_back(BCO->getOperand(0));
        } else if (auto *ITP = dyn_cast<IntToPtrOperator>(V)) {
            Stack.push_back(ITP->getValueOperand());
        } else if (auto *PTI = dyn_cast<PtrToIntOperator>(V)) {
            Stack.push_back(PTI->getPointerOperand());
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            if (GEP->hasAllConstantIndices())
                Stack.push_back(GEP->getOperand(0));
        } else if (auto *PN = dyn_cast<PHINode>(V)) {
            for (Value *PV : PN->incoming_values())
                Stack.push_back(PV);
        } else if (auto *SI = dyn_cast<SelectInst>(V)) {
            for (unsigned i = 1; i < SI->getNumOperands(); ++i)
                Stack.push_back(SI->getOperand(i));
        }
    }

    return false;
}

// Populate hoist map with existing lowered checks to avoid duplication
static void
findExistingChecks(LLVMContext &Ctx, const BasicBlock &BB, const Value *PCF,
                   std::unordered_map<const Value *, Value *> &HoistMap) {
    for (auto &I : BB) {
        if (auto *CB = dyn_cast<CallBase>(&I)) {
            if (CB->getCalledFunction() == PCF)
                HoistMap.emplace(simplify(CB->getOperand(1)),
                                 ConstantInt::getTrue(Ctx));
        }
    }
}

// Apply additional attributes for custom memory allocation functions
// FIXME: There exists a built-in isAllocationFn(), but replaceable global
// allocation functions in C++ will be labeled 'nobuiltin', and overridden at
// each call site as 'builtin' if invoked by a new/delete-expression. We only
// care about 'noalias' and 'nocapture', but can't infer this on custom memory
// functions, e.g. arena allocator
static bool applyMemoryAttributes(Function &F,
                                  const Optional<std::string> &Name) {
    const StringRef StrName(F.getName());
    MemFnType Type = Unknown;

    // 453/511.povray, 400/500/600.perlbench, 471.omnetpp, 482/523/623.xalancbmk
    if (Name) {
        if (!Name->rfind("pov::pov_malloc", 0))
            Type = Malloc;
        else if (!Name->rfind("pov::pov_calloc", 0))
            Type = Calloc;
        else if (!Name->rfind("pov::pov_realloc", 0))
            Type = Realloc;
        else if (isOperatorNew(*Name) ||
                 !Name->rfind("cSimpleModule::memAlloc", 0) ||
                 (!Name->rfind("xalanc", 0) &&
                  (Name->find("::allocateBlock") != std::string::npos ||
                   Name->find("::allocate") != std::string::npos)))
            Type = OpNew;
        else if (!Name->rfind("pov::pov_free", 0) ||
                 !Name->rfind("cSimpleModule::memFree", 0) ||
                 (!Name->rfind("xalanc", 0) &&
                  (Name->find("::destroyBlock") != std::string::npos ||
                   Name->find("::deallocate") != std::string::npos)))
            Type = Free;
    } else {
        if (StrName.equals("Perl_malloc"))
            Type = Malloc;
        else if (StrName.equals("Perl_calloc"))
            Type = Calloc;
        else if (StrName.equals("Perl_realloc"))
            Type = Realloc;
        else if (StrName.equals(getAllocateExceptionName()))
            Type = OpNew;
        else if (StrName.equals("Perl_mfree"))
            Type = Free;
    }

    switch (Type) {
    case Realloc:
        assert(F.getFunctionType()->getNumParams() > 0);
        if (!F.hasParamAttribute(0, Attribute::NoCapture))
            F.addParamAttr(0, Attribute::NoCapture);
        LLVM_FALLTHROUGH;
    case Malloc:
    case Calloc:
        if (!F.doesNotThrow())
            F.setDoesNotThrow();
        assert(!F.getFunctionType()->getReturnType()->isVoidTy());
        if (!F.hasAttribute(AttributeList::ReturnIndex, Attribute::NoAlias))
            F.addAttribute(AttributeList::ReturnIndex, Attribute::NoAlias);
        break;
    case OpNew:
        assert(!F.getFunctionType()->getReturnType()->isVoidTy());
        // FIXME: Attribute::NonNull depends on noexcept
        // if (!F.hasAttribute(AttributeList::ReturnIndex, Attribute::NonNull))
        //     F.addAttribute(AttributeList::ReturnIndex, Attribute::NonNull);
        if (!F.hasAttribute(AttributeList::ReturnIndex, Attribute::NoAlias))
            F.addAttribute(AttributeList::ReturnIndex, Attribute::NoAlias);
        break;
    case Free:
        if (!F.doesNotThrow())
            F.setDoesNotThrow();
        assert(F.getFunctionType()->getNumParams() > 0);
        if (!F.hasParamAttribute(0, Attribute::NoCapture))
            F.addParamAttr(0, Attribute::NoCapture);
        break;
    default:
        break;
    }

    return Type != Unknown;
}

/* Visitor for modifying instructions */
struct InstrumentVisitor : public InstVisitor<InstrumentVisitor> {
    IRBuilder<> IRB;
    bool LowerOnly;
    DTCallback &DCB;
    Function *RF;
    FunctionCallee TTF, PCF, PDF, PIF, SCF, PMCF, PRF;

    /* Information about current function */
    Function *currentFunc;
    bool isConstructorFunc, isDestructorFunc;
    MemFnType NoStrictType;
    const DominatorTree *DT;

    // Map of per-function stack pointers and their type (FP or VT)
    std::unordered_map<const AllocaInst *, bool> stackPointers;
    // Map of per-callsite checked pointers and their replacement values
    std::unordered_map<const Value *, Value *> HoistMap;

    InstrumentVisitor(LLVMContext &C, bool LO, DTCallback &CB)
        : IRB(C), LowerOnly(LO), DCB(CB) {}

    void visit(Module &M) {
        visitModule(M);
        InstVisitor::visit(M.begin(), M.end());
    }

    // Override hierarchy to allow skipping functions
    void visit(Function &F) {
        // If inlining is enabled, don't instrument ourselves
        if (F.isDeclaration() || isHQFunction(F))
            return;

        visitFunction(F);
        InstVisitor::visit(F.begin(), F.end());
    }

    void visit(BasicBlock &BB) {
        visitBasicBlock(BB);
        InstVisitor::visit(BB.begin(), BB.end());
    }

    void visit(Instruction &I) {
        visitInstruction(I);
        InstVisitor::visit(I);
    }

    void visitModule(Module &M) {
        TTF = Intrinsic::getDeclaration(&M, Intrinsic::type_test);
        RF = M.getFunction("realloc");
        createHQFunctions(IRB, M, &PCF, nullptr, &PDF, &PIF, &SCF, &PMCF,
                          nullptr, &PRF);
    }

    void visitFunction(Function &F) {
        auto Name = getDemangledName(F.getName());
        currentFunc = &F;
        isConstructorFunc = Name && isConstructor(F.getName());
        isDestructorFunc = Name && isDestructor(F.getName());
        assert(!(isConstructorFunc && isDestructorFunc) &&
               "Function cannot be constructor and destructor!");
        NoStrictType =
            UseStrictFP && SPECOverrides && LibraryFunctions
                ? getSPECNoStrictFP(F.getParent()->getModuleIdentifier(),
                                    F.getName())
                : MemFnType::Unknown;
        DT = nullptr;

        stackPointers.clear();

        if (SPECOverrides) {
            if (applyMemoryAttributes(F, Name))
                ++NumFnAttr;
        }
    }

#if defined(HQ_INTERFACE_UNSAFE_PID) ||                                        \
    defined(HQ_INTERFACE_UNSAFE_PID_CONCURRENT)
    void visitLoadInst(LoadInst &LI) {
        if (LI.getPointerAddressSpace() == PID_ADDR_SPACE) {
            errs() << LI << "\n";
            report_fatal_error("Load from address space not allowed!");
        }
    }
#endif /* HQ_INTERFACE_UNSAFE_PID || HQ_INTERFACE_UNSAFE_PID_CONCURRENT */

    void visitStoreInst(StoreInst &SI) {
        if (LowerOnly)
            return;

        Value *Dst = const_cast<Value *>(simplify(SI.getPointerOperand())),
              *Val = SI.getValueOperand();

        if (isFunctionPointer(*Val, UseStrictFP)) {
            // Send define/invalidate on stores to casted function pointers
            IRB.SetInsertPoint(SI.getNextNode());
            std::tie(Dst, Val) = getPtrAndVal(&SI);
            if (!Dst || !Val) {
                llvm::errs() << "visitStoreInst(): Unsupported StoreInst!\n";
                return;
            }

            Value *Args[] = {Dst, Val};
            // Either define or invalidate the pointer, based on value
            if (!isa<ConstantPointerNull>(Val)) {
                createCastedCall(IRB, PDF, Args);
                ++NumFPDef;

                // Track the lifetime of this function pointer if it is
                // stack-allocated
                if (auto *AI = dyn_cast<AllocaInst>(simplify(Dst, false, true)))
                    stackPointers.insert(std::make_pair(AI, true));
            } else {
                createCastedCall(IRB, PIF, MutableArrayRef<Value *>(Args, 1));
                ++NumFPInv;
            }
        } else if (isVTablePointer(*Val)) {
#ifndef NDEBUG
            assert((isConstructorFunc || isDestructorFunc) &&
                   "Store to vtable should occur in constructor/destructor!");
            const Value *VDst = simplify(Dst->stripInBoundsConstantOffsets());
            if (auto *A = dyn_cast<Argument>(VDst)) {
                assert(isObjectPointerVariable(*A));
            } else if (auto *GEPI = dyn_cast<GetElementPtrInst>(VDst)) {
                assert(isVTBaseOffsetVariable(*GEPI->getOperand(1)));
            } else if (auto *CB = dyn_cast<CallBase>(VDst)) {
                Function *F = CB->getCalledFunction();
                Optional<std::string> Name = F ? getDemangledName(F->getName())
                                               : Optional<std::string>();
                assert(Name && isOperatorNew(*Name));
            } else if (auto *LI = dyn_cast<LoadInst>(VDst)) {
                assert(isObjectPointerVariable(*LI));
            } else {
                report_fatal_error("Unrecognized vtable variable!");
            }
#endif /* NDEBUG */

            // Send define on object pointer to vtable
            IRB.SetInsertPoint(SI.getNextNode());

            Value *Args[] = {Dst, Val};
            createCastedCall(IRB, PDF, Args);
            ++NumVTDef;
        }
    }

    void visitTypeTest(IntrinsicInst &II) {
        Value *NewV = nullptr;

        IRB.SetInsertPoint(&II);

        assert(II.getNumArgOperands() == 2 &&
               "Unexpected number of type test intrinsic arguments!");
        auto *MAV = cast<MetadataAsValue>(II.getArgOperand(1));
        Value *Args[] = {nullptr, nullptr};

        Value *Op0 = II.getArgOperand(0);
        std::tie(Args[0], Args[1]) = getPtrAndVal(Op0);

        if (Args[1] &&
            (Args[0] || isa<PHINode>(Args[1]) || isa<SelectInst>(Args[1]))) {
        recheck:
            if (LowerOnly) {
                // Skip the type test if it was previously handled
                auto It = HoistMap.find(Args[1]);
                if (It != HoistMap.end()) {
                    NewV = It->second;
                    goto replace;
                }
            }

            // Both pointer and value are available, create the check
            if (Args[0]) {
                NewV = ConstantInt::getTrue(IRB.getContext());
                HoistMap.emplace(Args[1], NewV);
                createCastedCall(IRB, PCF, Args);
            } else if (auto *PN = dyn_cast<PHINode>(Args[1])) {
                // Move the check if it is not in the same basic block
                if (II.getParent() != PN->getParent()) {
                    if (LowerOnly)
                        findExistingChecks(IRB.getContext(), *PN->getParent(),
                                           PCF.getCallee(), HoistMap);
                    II.removeFromParent();
                    II.insertAfter(PN);
                    goto recheck;
                }

                // Override the insertion point because PHI nodes must be placed
                // together at the top of the basic block
                IRB.SetInsertPoint(II.getParent()->getFirstNonPHI());
                // Hoist the type test back onto each incoming basic block
                // to allow path-specific optimization, so create a new
                // PHINode here to merge the return value of each type test
                NewV = IRB.CreatePHI(II.getType(), PN->getNumIncomingValues());
                // Insert entry into map before recursing
                HoistMap.emplace(PN, NewV);

                for (unsigned i = 0; i < PN->getNumIncomingValues(); ++i) {
                    BasicBlock *BB = PN->getIncomingBlock(i);
                    Value *IV = PN->getIncomingValue(i);

                    // Check if the value has been handled before second pass
                    if (LowerOnly)
                        findExistingChecks(IRB.getContext(), *BB,
                                           PCF.getCallee(), HoistMap);

                    auto It = HoistMap.find(IV);
                    if (It == HoistMap.end()) {
                        if (auto *IVI = dyn_cast<Instruction>(IV)) {
                            assert(IVI->getNextNode() &&
                                   "Incoming PHI node value has no next "
                                   "instruction!");
                            IRB.SetInsertPoint(IVI->getNextNode());
                        } else
                            IRB.SetInsertPoint(BB->getTerminator());

                        Args[0] = IV;
                        Args[1] = MAV;
                        CallInst *TTC = createCastedCall(
                            IRB, TTF, MutableArrayRef<Value *>(Args));

                        cast<PHINode>(NewV)->addIncoming(TTC, BB);
                        // Recurse on the new type test
                        visitTypeTest(*cast<IntrinsicInst>(TTC));
                    } else
                        cast<PHINode>(NewV)->addIncoming(It->second, BB);
                }
            } else if (auto *SI = dyn_cast<SelectInst>(Args[1])) {
                // Same as above (PHINode), but for a SelectInst
                NewV = IRB.CreateSelect(SI->getCondition(), &II, &II);
                // Insert entry into map before recursing
                HoistMap.emplace(SI, NewV);

                for (unsigned i = 1; i < SI->getNumOperands(); ++i) {
                    Value *IV = SI->getOperand(i);
                    // Check if the value has been handled before second pass
                    if (LowerOnly) {
                        if (auto *I = dyn_cast<Instruction>(IV))
                            findExistingChecks(IRB.getContext(),
                                               *I->getParent(), PCF.getCallee(),
                                               HoistMap);
                    }

                    auto It = HoistMap.find(IV);
                    if (It == HoistMap.end()) {
                        IRB.SetInsertPoint(cast<SelectInst>(NewV));

                        Args[0] = IV;
                        Args[1] = MAV;
                        CallInst *TTC = createCastedCall(
                            IRB, TTF, MutableArrayRef<Value *>(Args));

                        cast<SelectInst>(NewV)->setOperand(i, TTC);
                        // Recurse on the new type test
                        visitTypeTest(*cast<IntrinsicInst>(TTC));
                    } else
                        cast<SelectInst>(NewV)->setOperand(i, It->second);
                }
            }
        } else if (Args[0] && isa<GetElementPtrInst>(Args[0]) && !Args[1]) {
            NewV = ConstantInt::getTrue(IRB.getContext());
            HoistMap.emplace(Args[0], NewV);

            // Only GetElementPtr pointer is available, must find the
            // values and insert checks
            SmallVector<Instruction *, 2> Values;
            findValFromPtr(*Args[0], Values);
            for (Instruction *I : Values) {
                assert(I->getNextNode() &&
                       "Incoming value has no next instruction!");
                IRB.SetInsertPoint(I->getNextNode());
                Args[1] = I;
                createCastedCall(IRB, PCF, Args);
            }
        } else {
            assert(((!Args[0] && Args[1]) || (Args[0] && !Args[1])) &&
                   "Must have pointer xor value!");
            // Only pointer or value is available, remove the check
            if (Args[0] ? Args[0]->hasName() : Args[1]->hasName())
                LLVM_DEBUG(dbgs() << currentFunc->getName()
                                  << ": Eliding check on direct call to '"
                                  << (Args[0] ? Args[0]->getName()
                                              : Args[1]->getName())
                                  << "'!\n");
            else
                LLVM_DEBUG(dbgs() << currentFunc->getName()
                                  << ": Eliding check on direct call to '"
                                  << (Args[0] ? *Args[0] : *Args[1]) << "'!\n");

            NewV = ConstantInt::getTrue(IRB.getContext());
            HoistMap.emplace(Args[1] ? Args[1] : Args[0], NewV);
        }

    replace:
        assert(II.getType() == NewV->getType());
        II.replaceAllUsesWith(NewV);
        II.eraseFromParent();

        ++NumChk;
    }

    void visitCallBase(CallBase &CB) {
        if (LowerOnly)
            return;

        const Function *F = CB.getCalledFunction();
        Optional<std::string> Name;

        if (F)
            Name = getDemangledName(F->getName());

        if (F == RF && NoStrictType == MemFnType::Realloc) {
            assert(CB.getFunctionType() == PRF.getFunctionType());
            CB.setCalledFunction(PRF);
            ++NumEarlyLib;
            return;
        }

        if (Name && isConstructor(*Name)) {
            // A constructor function is being called. Track the lifetime of
            // the object if it is stack-allocated, in order to invalidate
            // it when it goes out of scope, because a destructor function
            // is not always defined
            if (auto *AI = dyn_cast<AllocaInst>(
                    simplify(CB.getArgOperand(0), false, true)))
                stackPointers.insert(std::make_pair(AI, false));
        } else {
            // Insert checks on function calls with function pointer
            // arguments, since both the pointer and its value are not
            // available later
            for (Value *V : CB.arg_operands()) {
                if (isFunctionPointer(*V, UseStrictFP)) {
                    IRB.SetInsertPoint(&CB);
                    Value *Args[] = {
                        V, MetadataAsValue::get(
                               IRB.getContext(),
                               MDString::get(IRB.getContext(), "argument"))};
                    CallInst *NewC = createCastedCall(IRB, TTF, Args);

                    // Recursively lower type test to POINTER_CHECK_FUNCTION
                    visitTypeTest(*cast<IntrinsicInst>(NewC));
                }
            }
        }
    }

    void visitIntrinsicInst(IntrinsicInst &II) {
        switch (II.getIntrinsicID()) {
        default:
            break;
        case Intrinsic::lifetime_end:
            if (LowerOnly)
                return;

            // Send invalidate on out-of-scope stack-allocated objects/pointers
            // FIXME: Clang doesn't emit lifetime markers at O0
            if (auto *AI = dyn_cast<AllocaInst>(const_cast<Value *>(
                    simplify(II.getArgOperand(1), false, true)))) {
                auto Entry = stackPointers.find(AI);
                if (Entry != stackPointers.end()) {
                    IRB.SetInsertPoint(&II);

                    Value *Args[] = {AI};
                    createCastedCall(IRB, PIF, Args);

                    if (Entry->second)
                        ++NumFPInv;
                    else
                        ++NumVTInv;
                }
            }
            break;
        case Intrinsic::type_test: {
            // Fetch the checked call
            CallBase *CC = getCheckedCall(II);
            if (CC) {
                // Eliminate the type test if the checked call is optimizable
                Value *V = optimizeCheckedCall(*CC);
                if (V) {
                    LLVM_DEBUG(dbgs()
                               << currentFunc->getName()
                               << ": Eliding check on optimizable call to '"
                               << V->getName() << "'!\n");

                    CC->setCalledOperand(V);
                    II.replaceAllUsesWith(ConstantInt::getTrue(II.getType()));
                    II.eraseFromParent();

                    ++NumOptChk;
                    break;
                }
            } else {
                // At times, cfi-nvcall/cfi-vcall can insert intermediate type
                // checks on casts before another a subsequent type check on a
                // vtable load and call. In this case, there is no direct
                // checked call, so it can be removed
                LLVM_DEBUG(dbgs()
                           << currentFunc->getName() << ": Eliding check on '"
                           << simplify(II.getArgOperand(0))->getName()
                           << "' without subsequent call!\n");

                II.replaceAllUsesWith(ConstantInt::getTrue(II.getType()));
                II.eraseFromParent();

                ++NumOptChk;
                break;
            }

            HoistMap.clear();
            // Recursively lower type test to POINTER_CHECK_FUNCTION
            if (LowerOnly) {
                // In the second pass, populate the map with existing checks to
                // avoid generating duplicate checks
                findExistingChecks(IRB.getContext(), *II.getParent(),
                                   PCF.getCallee(), HoistMap);
            }
            visitTypeTest(II);
        } break;
        case Intrinsic::memcpy:
            if (NoStrictType == MemCpy) {
                Value *A0 = const_cast<Value *>(
                          simplify(II.getArgOperand(0), false)),
                      *A1 = const_cast<Value *>(
                          simplify(II.getArgOperand(1), false)),
                      *A2 = II.getArgOperand(2);
                assert(cast<ConstantInt>(II.getArgOperand(3))->isZeroValue());
                // Different number of arguments, recreate the call
                IRB.SetInsertPoint(&II);
                Value *Args[] = {A0, A1, A2};
                createCastedCall(IRB, PMCF, Args);
                ++NumEarlyLib;
            }
            break;
        }
    }

    void visitReturnInst(ReturnInst &RI) {
        if (LowerOnly)
            return;

        if (isDestructorFunc && isNonBaseDestructor(currentFunc->getName())) {
            // Send invalidate on vtable pointer during object destruction
            IRB.SetInsertPoint(&RI);

            assert(currentFunc->arg_size() >= 1 &&
                   "Unexpected number of arguments on C++ destructor "
                   "function!");
            Value *Args[] = {currentFunc->arg_begin()};
            assert(isObjectPointerVariable(*Args[0]) &&
                   "Unexpected non-object pointer argument in C++ destructor "
                   "function!");
            createCastedCall(IRB, PIF, Args);

            ++NumVTInv;
        } else {
            Value *V = RI.getReturnValue();
            // Insert checks on function calls with function pointer return,
            // since both the pointer and its value are not available later
            if (V && isFunctionPointer(*V, UseStrictFP)) {
                // Check must occur immediately after the definition,
                // because it may overwritten later in the same function
                Value *SV = const_cast<Value *>(simplify(V));
                assert(isa<Instruction>(SV));
                IRB.SetInsertPoint(cast<Instruction>(SV)->getNextNode());
                Value *Args[] = {
                    SV, MetadataAsValue::get(
                            IRB.getContext(),
                            MDString::get(IRB.getContext(), "return"))};
                CallInst *NewC = createCastedCall(IRB, TTF, Args);

                HoistMap.clear();
                // Recursively lower type test to POINTER_CHECK_FUNCTION
                visitTypeTest(*cast<IntrinsicInst>(NewC));
            }
        }
    }
};

/* Create CFI instrumentation */
static bool createCFIInstrumentation(bool LowerOnly, DTCallback DCB,
                                     Module &M) {
    LLVMContext &C = M.getContext();
    Function *TypeTestFunction =
        M.getFunction(Intrinsic::getName(Intrinsic::type_test));

    // Skip if not enabled, or no type tests on the second pass
    if (!RunCFI || (LowerOnly && !TypeTestFunction))
        return false;

    InstrumentVisitor IV(C, LowerOnly, DCB);
    IV.visit(M);

    bool Changed = NumFPDef || NumFPInv || NumVTDef || NumVTInv || NumChk ||
                   NumOptChk || NumFnAttr || NumEarlyLib;
    if (Changed) {
        outs() << M.getName() << ": Instrumented function pointers ("
               << NumFPDef << " defines, " << NumFPInv
               << " invalidates), vtable pointers (" << NumVTDef << " defines, "
               << NumVTInv << " invalidates), checks (" << NumChk
               << " created, " << NumOptChk << " optimized); ";
        if (NumEarlyLib)
            outs() << NumEarlyLib
                   << " instrumented/redirected library functions; ";
        if (NumFnAttr)
            outs() << NumFnAttr << " function attributes";
        outs() << "\n";

        // Remove declaration of builtin type test intrinsic
        if (TypeTestFunction) {
            if (TypeTestFunction->getNumUses())
                report_fatal_error("Uses of type test intrinsic remain!");
            TypeTestFunction->eraseFromParent();
        }
    }

    return Changed;
}

/* Implementation for legacy pass manager */
void CFIInstrumentLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
    if (CFIDominatorAnalysis) {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addPreserved<DominatorTreeWrapperPass>();
    }
    AU.setPreservesCFG();
}

bool CFIInstrumentLegacyPass::runOnModule(Module &M) {
    auto DTCallbacks = [this](Function &F) -> const DominatorTree * {
        return CFIDominatorAnalysis && !F.isDeclaration()
                   ? &this->getAnalysis<DominatorTreeWrapperPass>(F)
                          .getDomTree()
                   : nullptr;
    };

    return createCFIInstrumentation(LowerOnly, DTCallbacks, M);
}

char CFIInstrumentLegacyPass::ID = 0;

// Use this because RegisterPass<...>(...) does not support dependent passes
INITIALIZE_PASS_BEGIN(CFIInstrumentLegacyPass, DEBUG_TYPE,
                      "CFI Instrumentation Pass", false, false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_END(CFIInstrumentLegacyPass, DEBUG_TYPE,
                    "CFI Instrumentation Pass", false, false)

// Force DCE pass afterwards to remove unused pointer casts, which may otherwise
// cause module verification to fail (e.g. cast between PHINodes)
static RegisterStandardPasses CFIRegisterEarly(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PassRegistry *PR = PassRegistry::getPassRegistry();
        initializeCFIInstrumentLegacyPassPass(*PR);
        PM.add(new CFIInstrumentLegacyPass());
        PM.add(createDeadCodeEliminationPass());
#ifndef NDEBUG
        PM.add(createVerifierPass());
#endif /* NDEBUG */
    });

static RegisterStandardPasses CFIRegisterL0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PassRegistry *PR = PassRegistry::getPassRegistry();
        initializeCFIInstrumentLegacyPassPass(*PR);
        PM.add(new CFIInstrumentLegacyPass());
        PM.add(createDeadCodeEliminationPass());
#ifndef NDEBUG
        PM.add(createVerifierPass());
#endif /* NDEBUG */
    });

// This is the custom endpoint for lowering type tests again after whole
// program devirtualization. Not needed if the latter is not enabled. See
// top of file.
static RegisterStandardPasses CFIRegisterLTOPreLTT(
    PassManagerBuilder::EP_FullLinkTimeOptimizationPreLowerTypeTests,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PM.add(new CFIInstrumentLegacyPass(true));
        PM.add(createDeadCodeEliminationPass());
#ifndef NDEBUG
        PM.add(createVerifierPass());
#endif /* NDEBUG */
    });

/* Implementation for new pass manager */
void CFIInstrumentPass::create(ModulePassManager &MPM, bool LowerOnly) {
    if (CFIDominatorAnalysis)
        MPM.addPass(RequireAnalysisPass<DominatorTreeAnalysis, Module>());
    MPM.addPass(CFIInstrumentPass(LowerOnly));
}

PreservedAnalyses CFIInstrumentPass::run(Module &M,
                                         ModuleAnalysisManager &MAM) {
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    auto DTCallbacks = [&FAM](Function &F) -> const DominatorTree * {
        return CFIDominatorAnalysis && !F.isDeclaration()
                   ? &FAM.getResult<DominatorTreeAnalysis>(F)
                   : nullptr;
    };

    if (!createCFIInstrumentation(LowerOnly, DTCallbacks, M))
        return PreservedAnalyses::all();

    PreservedAnalyses PA = PreservedAnalyses::none();
    PA.preserve<LoopAnalysis>();
    PA.preserveSet<CFGAnalyses>();
    PA.preserve<DominatorTreeAnalysis>();
    PA.preserve<FunctionAnalysisManagerModuleProxy>();
    return PA;
}

#undef DEBUG_TYPE
