#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "config.h"
#include "runtime.h"
#include "syscalls.h"
#include "utils.h"

using namespace llvm;

/* Utility functions */
CallInst *createCastedCall(IRBuilder<> &IRB, FunctionCallee &FC,
                           MutableArrayRef<Value *> Args) {
    FunctionType *FTy = FC.getFunctionType();

    // Insert casts on arguments if necessary
    assert(Args.size() == FTy->getNumParams() &&
           "Number of arguments don't match callee type!");
    for (unsigned i = 0; i < Args.size(); ++i) {
        Type *DTy = FTy->getParamType(i), *STy = Args[i]->getType();
        if (STy != DTy)
            Args[i] = castToTy(&IRB, Args[i], *DTy);
    }

    return IRB.CreateCall(FC, Args);
}

void createHQFunctions(IRBuilder<> &IRB, Module &M, FunctionCallee *PCF,
                       FunctionCallee *PCIF, FunctionCallee *PDF,
                       FunctionCallee *PIF, FunctionCallee *SCF,
                       FunctionCallee *PMCF, FunctionCallee *PFF,
                       FunctionCallee *PRF) {
    auto &C = M.getContext();

    // Create basic types
    Type *VTy = IRB.getVoidTy();
    PointerType *PTy = IRB.getInt8PtrTy();
    PointerType *PPTy = PointerType::getUnqual(PTy);
    IntegerType *I64Ty = IntegerType::getInt64Ty(C);

    // Runtime attributes for sending messages
    if (PCF || PCIF || PDF || PIF || SCF) {
        Attribute FnIMWNU[] =
        { Attribute::get(C, Attribute::InaccessibleMemOnly),
#if INTERFACE_TYPE == INTERFACE_TYPE_OPAE ||                                   \
    INTERFACE_TYPE == INTERFACE_TYPE_PAGES ||                                  \
    INTERFACE_TYPE == INTERFACE_TYPE_ZERO
          Attribute::get(C, Attribute::Speculatable),
          Attribute::get(C, Attribute::WriteOnly),
#endif /* INTERFACE_TYPE */
          Attribute::get(C, Attribute::NoUnwind) },
                  ArgRNNC[] = {Attribute::get(C, Attribute::ReadNone),
                               Attribute::get(C, Attribute::NoCapture)};
        auto IMWNU = AttributeSet::get(C, FnIMWNU),
             RNNC = AttributeSet::get(C, ArgRNNC);
        auto ALP =
            AttributeList::get(C, {{AttributeList::FirstArgIndex, RNNC},
                                   {AttributeList::FirstArgIndex + 1, RNNC},
                                   {AttributeList::FunctionIndex, IMWNU}});

        // All of the following message functions never throw exceptions
        // (nounwind); if an error occurs, they will immediately abort the
        // program.
        // The three pointer functions treat all pointer arguments as
        // integers that are never dereferenced (nocapture, readnone), and
        // only store their values into the interface, which is otherwise
        // inaccessible (inaccessiblememonly). For certain interfaces, this
        // operation does not perform any reads (writeonly), and has no
        // other side effects (speculatable).
        if (PCF)
            *PCF = M.getOrInsertFunction(STR(POINTER_CHECK_FUNCTION), ALP, VTy,
                                         PPTy, PTy);
        if (PCIF)
            *PCIF = M.getOrInsertFunction(
                STR(POINTER_CHECK_INVALIDATE_FUNCTION), ALP, VTy, PPTy, PTy);
        if (PDF)
            *PDF = M.getOrInsertFunction(STR(CFI_POINTER_DEFINE_FUNCTION), ALP,
                                         VTy, PPTy, PTy);
        if (PIF) {
            auto ALI =
                AttributeList::get(C, {{AttributeList::FirstArgIndex, RNNC},
                                       {AttributeList::FunctionIndex, IMWNU}});
            *PIF = M.getOrInsertFunction(STR(POINTER_INVALIDATE_FUNCTION), ALI,
                                         VTy, PPTy);
        }
        if (SCF) {
            auto ALS =
                AttributeList::get(C, AttributeList::FunctionIndex, IMWNU);
            *SCF = M.getOrInsertFunction(STR(SYSCALL_FUNCTION), ALS, VTy);
        }
        if (PMCF)
            *PMCF = M.getOrInsertFunction(STR(POINTER_COPY_FUNCTION), ALP, VTy,
                                          PTy, PTy, I64Ty);
    }

    if (PFF || PRF) {
        std::pair<unsigned, Attribute> NoC = {
            AttributeList::FirstArgIndex,
            Attribute::get(C, Attribute::NoCapture)};
        if (PFF) {
            auto ALFF = AttributeList::get(C, {NoC});
            *PFF = M.getOrInsertFunction(STR(POINTER_FREE_FUNCTION), ALFF, VTy,
                                         PTy);
        }

        if (PRF) {
            auto ALRF =
                AttributeList::get(C, {{AttributeList::ReturnIndex,
                                        Attribute::get(C, Attribute::NoAlias)},
                                       NoC});
            *PRF = M.getOrInsertFunction(STR(POINTER_REALLOC_FUNCTION), ALRF,
                                         PTy, PTy, I64Ty);
        }
    }
}

bool createSyscallMessage(IRBuilder<> &IRB, CallBase &CB, FunctionCallee &SCF,
                          const DominatorTree *DT,
                          const PostDominatorTree *PDT) {
    Instruction *InsertPt = nullptr;
    BasicBlock *BB = CB.getParent();

    if (BB->getParent()->hasFnAttribute(Attribute::AlwaysInline))
        return false;

    // Given an instruction CB, find the insertion point for system call
    // messages. If dominator analysis is available, this is the first basic
    // block that dominates CB and CB post-dominates it, without function calls
    // in subsequent basic blocks. Otherwise, find the last non-call instruction
    // before CB in its basic block.
    if (DT && PDT) {
        BasicBlock *Earliest = nullptr;

        // Search through all predecessors of BB
        for (auto it = idf_begin(BB), end = idf_end(BB); it != end; ++it) {
            if (*it == BB)
                continue;

            if (!Earliest) {
                assert(DT->getNode(*it) && DT->getNode(BB) &&
                       PDT->getNode(BB) && PDT->getNode(*it) &&
                       "Basic blocks must be in dominator trees!");
                // Find the earliest satisfying basic block
                if (DT->dominates(*it, BB) && PDT->dominates(BB, *it))
                    Earliest = *it;
            }

            // Invalidate result if current basic block contains a function
            // call, which could perform a system call
            if (Earliest) {
                for (Instruction &I : **it) {
                    if (isa<CallBase>(I) && !isa<IntrinsicInst>(I)) {
                        Earliest = nullptr;
                        break;
                    }
                }
            }
        }

        if (Earliest)
            InsertPt = getFirstNonAllocaInsertionPt(*Earliest);
    }

    // Otherwise, search backwards from the callsite until the beginning of the
    // basic block, or a function call or PHINode is found
    if (!InsertPt) {
        InsertPt = &CB;
        auto *prevI = CB.getPrevNode();
        while (prevI && (!isa<CallBase>(prevI) || isa<IntrinsicInst>(prevI)) &&
               !isa<PHINode>(prevI)) {
            InsertPt = prevI;
            prevI = InsertPt->getPrevNode();
        }
    }

    IRB.SetInsertPoint(InsertPt);
    IRB.CreateCall(SCF);
    return true;
}

void createGlobalInit(Module &M,
                      const SmallVectorImpl<Constant *> &InitGlobalsInternal,
                      const SmallVectorImpl<Constant *> &InitGlobalsExternal) {
    // Create a global constructor function that is called at startup
    LLVMContext &C = M.getContext();
    IRBuilder<> IRB(C);

    // Create types
    Type *VTy = IRB.getVoidTy();
    IntegerType *I64Ty = IRB.getInt64Ty();
    PointerType *PI64Ty = PointerType::getUnqual(I64Ty);
    auto IAMNoU = AttributeSet::get(
        C, {Attribute::get(C, Attribute::InaccessibleMemOrArgMemOnly),
            Attribute::get(C, Attribute::NoUnwind)});
    auto ALI = AttributeList::get(C, AttributeList::FunctionIndex, IAMNoU);

    // Create module-specific initialization function
    assert(!M.getFunction(STR(INIT_FUNCTION_EXTERNAL)) &&
           "Module initialization function already exists!");
    auto *MIF = Function::Create(FunctionType::get(VTy, false),
                                 GlobalValue::InternalLinkage,
                                 STR(INIT_FUNCTION_EXTERNAL), &M);
    appendToGlobalCtors(M, MIF, 0);

    // Create runtime initialization call
    FunctionCallee InitFunction = M.getOrInsertFunction(
        STR(CFI_INIT_GLOBALS_FUNCTION), ALI, VTy, PI64Ty, I64Ty, PI64Ty, I64Ty);

    // Initialize the basic block
    BasicBlock *BB = BasicBlock::Create(C, "entry", MIF);
    IRB.SetInsertPoint(ReturnInst::Create(C, BB));

    assert(InitGlobalsInternal.size() || InitGlobalsExternal.size());
    Constant *InitArrayInternal, *InitArrayExternal;
    // For internal variables, create array in labeled section and add call
    if (InitGlobalsInternal.size()) {
        ArrayType *InitTy = ArrayType::get(InitGlobalsInternal[0]->getType(),
                                           InitGlobalsInternal.size());
        GlobalVariable *GV =
            new GlobalVariable(M, InitTy, true, GlobalValue::ExternalLinkage,
                               ConstantArray::get(InitTy, InitGlobalsInternal),
                               STR(INIT_ARRAY_INTERNAL));
        // Prevent runtime symbol preemption
        GV->setDSOLocal(true);
        // Set special section
        GV->setSection(STR(INIT_SECTION_INTERNAL));
        InitArrayInternal = GV;
    } else
        InitArrayInternal =
            Constant::getNullValue(Type::getInt8PtrTy(M.getContext()));

    // For external variables, create array and pass it to the call
    if (InitGlobalsExternal.size()) {
        // Insert call to iterate sensitive pointers and send define messages
        ArrayType *InitTy = ArrayType::get(InitGlobalsExternal[0]->getType(),
                                           InitGlobalsExternal.size());
        GlobalVariable *GV =
            new GlobalVariable(M, InitTy, true, GlobalValue::InternalLinkage,
                               ConstantArray::get(InitTy, InitGlobalsExternal),
                               STR(INIT_ARRAY_EXTERNAL));
        // Prevent runtime symbol preemption
        GV->setDSOLocal(true);
        InitArrayExternal = GV;
    } else
        InitArrayExternal =
            Constant::getNullValue(Type::getInt8PtrTy(M.getContext()));

    IRB.CreateCall(InitFunction,
                   {IRB.CreatePointerCast(InitArrayInternal, PI64Ty),
                    ConstantInt::get(I64Ty, InitGlobalsInternal.size()),
                    IRB.CreatePointerCast(InitArrayExternal, PI64Ty),
                    ConstantInt::get(I64Ty, InitGlobalsExternal.size())});
}

// Determine if global variable should be skipped during instrumentation. This
// means that the GV does not have an initializer, is an LLVM-internal variable,
// is unused, or a C++-internal variable.
static bool shouldSkipGV(const GlobalVariable &GV, bool LTO,
                         std::string *Demangled) {
    // Skip variables that are not initialized, or may change early at runtime
    // FIXME: can a symbol with common linkage have two conflicting definitions?
    if (!GV.hasInitializer() || GV.isExternallyInitialized())
        return true;

    // Skip unused global variables
    if (LTO && !GV.getNumUses())
        return true;

    // Skip LLVM-internal variables
    // FIXME: Brittle string matching
    const StringRef Name = GV.getName();
    if (Name.startswith("llvm."))
        return true;

    // Skip C++-internal variables, excluding vtables
    if (Demangled) {
        auto OptDemangled = getDemangledName(Name);
        if (OptDemangled) {
            *Demangled = *OptDemangled;
            if (isTypeInfo(*OptDemangled) || isTypeInfoName(*OptDemangled) ||
                isVTableTable(*OptDemangled))
                return true;
        }
    }

    return false;
}

// Unpack a constant and track GetElementPtr indices to its contents. Can
// specify whether to include only function pointers and/or vtable pointers,
// as well as an additional exclude list.
using IndexList = SmallVector<unsigned, 2>;
static SmallVector<std::pair<const Value *, IndexList>, 4>
unpackValue(const Value &I, bool onlyFP, bool onlyVT,
            const ArrayRef<const Value *> Exclude) {
    const bool includeAll = !onlyFP && !onlyVT;
    SmallVector<std::pair<const Value *, IndexList>, 4> Pointers;

    if (auto *GV = dyn_cast<GlobalValue>(&I)) {
        // Check if this is a function pointer
        if ((includeAll || (onlyFP && isFunctionPointerTy(*GV->getType()))) &&
            none_of(Exclude, [&](auto &V) { return GV == V; }))
            Pointers.emplace_back(GV, IndexList());
    } else if (auto *CA = dyn_cast<ConstantAggregate>(&I)) {
        // Track indexes through arrays and structs
        for (unsigned i = 0; i < CA->getNumOperands(); ++i) {
            auto Elem =
                unpackValue(*CA->getOperand(i), onlyFP, onlyVT, Exclude);
            for (auto &P : Elem)
                P.second.emplace_back(i);
            Pointers.append(Elem.begin(), Elem.end());
        }
    } else if (auto *CD = dyn_cast<ConstantData>(&I)) {
        if (includeAll) {
            if (auto *CAZ = dyn_cast<ConstantAggregateZero>(CD)) {
                // Track indexes through arrays, structs, and vectors
                for (unsigned i = 0; i < CAZ->getNumElements(); ++i) {
                    auto Elem = unpackValue(*CAZ->getElementValue(i), onlyFP,
                                            onlyVT, Exclude);
                    for (auto &P : Elem)
                        P.second.emplace_back(i);
                    Pointers.append(Elem.begin(), Elem.end());
                }
            } else if (auto *CDS = dyn_cast<ConstantDataSequential>(CD)) {
                for (unsigned i = 0; i < CDS->getNumOperands(); ++i)
                    Pointers.emplace_back(CDS->getOperand(i), i);
            } else
                Pointers.emplace_back(CD, IndexList());
        }
    } else if (auto *CE = dyn_cast<ConstantExpr>(&I)) {
        // Track indexes through type casts
        if (CE->isCast()) {
            auto *V = CE->getOperand(0);
            if (includeAll ||
                (onlyFP && (isFunctionPointerTy(*CE->getType()) ||
                            isFunctionPointerTy(*V->getType())))) {
                auto Elem = unpackValue(*V, onlyFP, onlyVT, Exclude);
                if (Elem.size())
                    Pointers.append(Elem.begin(), Elem.end());
            }
        } else if (CE->isGEPWithNoNotionalOverIndexing()) {
            auto *VT = CE->stripInBoundsConstantOffsets();
            const Optional<std::string> Name = getDemangledName(VT->getName());
            // Check if this is a vtable
            if (includeAll || (onlyVT && Name && isVTable(*Name) &&
                               isStructPointerTy(*VT->getType())))
                Pointers.emplace_back(CE, IndexList());
        }
    }

    return Pointers;
}

void instrumentGlobalVariables(
    Module &M, StructType &STy, bool LTO, const ArrayRef<const Value *> Exclude,
    SmallVectorImpl<Constant *> &InitGlobalsInternal,
    SmallVectorImpl<Constant *> &InitGlobalsExternal) {
    SmallVector<Constant *, 2> Indexes;
    LLVMContext &C = M.getContext();
    // Structure index type must be 32-bit integer
    IntegerType *SITy = IntegerType::getInt32Ty(C);

    for (GlobalVariable &GV : M.globals()) {
        std::string Demangled;
        // Skip certain global variables
        if (shouldSkipGV(GV, LTO, &Demangled))
            continue;

        Constant *V;
        // For CFI, instrument all function pointers and vtables in GVs, unless
        // the GV is already a vtable. Otherwise, instrument all values in GVs.
        auto FPs = unpackValue(*GV.getInitializer(), true, !isVTable(Demangled),
                               Exclude);
        for (auto &P : FPs) {
            // No values found
            if (!P.first)
                continue;

            // Generate the GEP expression for the address of this value, given
            // indexes into its enclosing aggregate array/struct constant
            if (P.second.size()) {
                Indexes.clear();
                // Always insert zero index for the global variable itself
                Indexes.emplace_back(ConstantInt::get(SITy, 0));
                for (auto I = P.second.rbegin(), E = P.second.rend(); I != E;
                     ++I)
                    Indexes.emplace_back(ConstantInt::get(SITy, *I));

                V = ConstantExpr::getGetElementPtr(nullptr, &GV, Indexes, true);
            } else
                V = &GV;

            auto *CS = ConstantStruct::get(
                &STy, ConstantExpr::getPointerCast(V, STy.getElementType(0)),
                cast<Constant>(castToTy(nullptr, const_cast<Value *>(P.first),
                                        *STy.getElementType(1))));
            auto *TargetGV = dyn_cast<GlobalValue>(simplify(P.first));
            if (TargetGV && TargetGV->isDeclarationForLinker())
                InitGlobalsExternal.push_back(CS);
            else
                InitGlobalsInternal.push_back(CS);
        }
    }
}

const Value *resolveGEP(const GEPOperator *GEP, bool initGEP) {
    if (GEP->hasAllZeroIndices())
        return GEP->getPointerOperand();
    else if (initGEP && GEP->hasAllConstantIndices()) {
        const Constant *C = nullptr;
        auto *V = GEP->getPointerOperand();
        auto II = GEP->idx_begin(), IE = GEP->idx_end();
        if (auto *GV = dyn_cast<GlobalVariable>(V)) {
            if (GV->isConstant() && GV->hasDefinitiveInitializer()) {
                C = GV->getInitializer();
                ++II;
            }
        } else if (auto *CA = dyn_cast<ConstantAggregate>(V))
            C = CA;

        while (C && II != IE)
            C = C->getAggregateElement(cast<Constant>(*II++));
        return C;
    }

    return nullptr;
}

const Value *simplify(const Value *V, bool initGEP, bool skipGEP) {
    while (true) {
        if (auto *BCO = dyn_cast<BitCastOperator>(V)) {
            V = BCO->getOperand(0);
            continue;
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            if (skipGEP) {
                V = GEP->getPointerOperand();
                continue;
            }

            auto *NewV = resolveGEP(GEP, initGEP);
            if (NewV) {
                V = NewV;
                continue;
            }
        } else if (auto *II = dyn_cast<IntrinsicInst>(V)) {
            switch (II->getIntrinsicID()) {
            // Ignore invariant.group intrinsic
            case Intrinsic::launder_invariant_group:
            case Intrinsic::strip_invariant_group:
                V = II->getArgOperand(0);
                continue;
            }
        }

        break;
    }

    return V;
}

bool isEquivalent(const Value *V1, const Value *V2) {
    V1 = simplify(V1);
    V2 = simplify(V2);

    if (V1 == V2)
        return true;
    else if (isa<ConstantExpr>(V1) && isa<ConstantExpr>(V2)) {
        auto *C1 = cast<ConstantExpr>(V1), *C2 = cast<ConstantExpr>(V2);
        if (C1->getOpcode() == C2->getOpcode())
            return isEquivalent(C1->getOperand(0), C2->getOperand(0));
        return false;
    } else if (isa<ConstantPointerNull>(V1) && isa<ConstantPointerNull>(V2)) {
        return true;
    } else if (isa<PHINode>(V1) && isa<PHINode>(V2)) {
        auto *P1 = cast<PHINode>(V1), *P2 = cast<PHINode>(V2);
        if (P1->getNumIncomingValues() != P2->getNumIncomingValues())
            return false;
        for (unsigned i = 0; i < P1->getNumIncomingValues(); ++i) {
            if (!isEquivalent(P1->getIncomingValue(i), P2->getIncomingValue(i)))
                return false;
        }

        return true;
    } else if (isa<SelectInst>(V1) && isa<SelectInst>(V2)) {
        auto *S1 = cast<SelectInst>(V1), *S2 = cast<SelectInst>(V2);
        for (unsigned i = 1; i < S1->getNumOperands(); ++i) {
            if (!isEquivalent(S1->getOperand(i), S2->getOperand(i)))
                return false;
        }

        return true;
    } else {
        errs() << *V1 << ", " << *V2 << "\n";
        report_fatal_error("isEquivalent(): Unsupported instruction!");
    }

    return false;
}

Instruction *getFirstNonAllocaInsertionPt(BasicBlock &BB) {
    auto *I = BB.getFirstNonPHI();
    while (I && isa<AllocaInst>(I))
        I = I->getNextNode();
    return I;
}

bool getSysCallsOnly() {
    Optional<std::string> syscalls_only =
        sys::Process::GetEnv("HQ_SYSCALLS_ONLY");
    return syscalls_only && *syscalls_only != "0";
}

const Optional<std::string> getInlinePath() {
    return sys::Process::GetEnv("HQ_INLINE_PATH");
}

static void postInlineCallback(Module &M, const StringSet<> &SS) {
    // Set linked functions to internal linkage, for removal by GlobalDCE
    for (auto &S : SS) {
        auto *F = M.getFunction(S.getKey());
        if (F)
            F->setLinkage(GlobalValue::InternalLinkage);
    }
}

bool performInlining(Module &M, const cl::opt<std::string> &Path) {
    std::string InlinePath;

    if (!Path.empty())
        InlinePath = Path;
    else {
        auto &V = getInlinePath();
        if (V)
            InlinePath = *V;
    }

    if (InlinePath.empty())
        return false;

    auto MB = MemoryBuffer::getFile(InlinePath);
    if (std::error_code EC = MB.getError())
        report_fatal_error("Error '" + EC.message() +
                           "' while loading interface bitcode!\n");

    auto IM = parseBitcodeFile(MB->get()->getMemBufferRef(), M.getContext());
    if (std::error_code EC = MB.getError())
        report_fatal_error("Error '" + EC.message() +
                           "' while parsing interface bitcode!\n");

    outs() << M.getName() << ": Inlining interface bitcode '"
           << IM->get()->getName() << "'\n";

    return Linker::linkModules(M, std::move(IM.get()), Linker::LinkOnlyNeeded,
                               postInlineCallback);
}

MemFnType getSPECNoStrictFP(const StringRef MName, const StringRef FName) {
    if (MName.contains("400.perlbench") &&
        FName.equals("Perl_safesysrealloc")) {
        // Generic stack with tagged unions that decays into generic pointers
        return MemFnType::Realloc;
    } else if (MName.contains("453.povray") || MName.contains("511.povray_r")) {
        if (FName.equals("_ZN3pov11pov_reallocEPvmPKciS2_")) {
            // Array of functions decays into generic pointers
            return MemFnType::Realloc;
        } else if (FName.equals("_ZN3pov21POVFPU_RemoveFunctionEj")) {
            // Stack allocation decays into generic pointer after inlining
            return MemFnType::MemCpy;
        }
    } else if (MName.contains("525.x264_r") && FName.equals("mbcmp_init")) {
        // Dispatch array decays into generic pointer after inlining
        return MemFnType::MemCpy;
    }
    return MemFnType::Unknown;
}

bool isHQFunction(const Function &F) { return F.getName().startswith("__hq_"); }

bool isCFIPointerFunction(const Function &F) {
    return F.getName().startswith("__hq_cfi_pointer_");
}

bool isCString(const Value &Val) {
    const auto *V = Val.stripPointerCasts();
    if (auto *GV = dyn_cast<GlobalVariable>(V)) {
        if (GV->isConstant() && GV->hasDefinitiveInitializer())
            if (auto *CDS =
                    dyn_cast<ConstantDataSequential>(GV->getInitializer()))
                return CDS->isCString();
    }
    return false;
}

bool isFunctionPointer(const Value &Val, bool strictFP, bool subTy) {
    DedupVector<const Value *, 4> Stack;

    // Walk the definition of the value and check each type
    // This is necessary to handle e.g. unions, which are converted to a struct
    // containing the maximum size subtype, and bitcasted to other types
    Stack.push_back(&Val);
    while (!Stack.empty()) {
        const auto *V = Stack.pop_back_val();

        if (isFunctionPointerTy(*V->getType(), subTy))
            return true;

        if (auto *BCO = dyn_cast<BitCastOperator>(V)) {
            Stack.push_back(BCO->getOperand(0));
        } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            const auto *NewV = resolveGEP(GEP);
            if (NewV)
                Stack.push_back(NewV);
        } else if (auto *II = dyn_cast<IntrinsicInst>(V)) {
            switch (II->getIntrinsicID()) {
            // Ignore invariant.group intrinsic
            case Intrinsic::launder_invariant_group:
            case Intrinsic::strip_invariant_group:
                Stack.push_back(II->getArgOperand(0));
            }
            break;
        } else if (auto *PN = dyn_cast<PHINode>(V)) {
            for (Value *PV : PN->incoming_values())
                Stack.push_back(PV);
        } else if (auto *SI = dyn_cast<SelectInst>(V)) {
            for (unsigned i = 1; i < SI->getNumOperands(); ++i)
                Stack.push_back(SI->getOperand(i));
        }

        if (Stack.empty()) {
            // At the last root, check if it has any other uses that are casts.
            // This is because dynamic memory functions typically return a void
            // pointer (i8 *), and the InstCombine pass will change GEP of a
            // BitCast directly into a GEP on the root, obscuring the type.
            for (const User *U : V->users()) {
                if (auto *BCO = dyn_cast<BitCastOperator>(U))
                    Stack.push_back(BCO);
            }

            if (subTy && !strictFP && isInt8PointerTy(*V->getType()))
                return true;
        }
    }

    return false;
}

/* Type predicates */
Value *castToTy(IRBuilder<> *IRB, Value *V, Type &DTy) {
    auto &STy = *V->getType();
    if (&STy == &DTy)
        return V;
    if (STy.isFloatingPointTy()) {
        if (DTy.isFloatingPointTy())
            return IRB ? IRB->CreateFPCast(V, &DTy)
                       : ConstantExpr::getFPCast(cast<Constant>(V), &DTy);
        else if (DTy.isIntegerTy())
            return IRB ? IRB->CreateFPToUI(V, &DTy)
                       : ConstantExpr::getFPToUI(cast<Constant>(V), &DTy);
        else if (DTy.isArrayTy() || DTy.isPointerTy()) {
            const auto Sz = STy.getScalarSizeInBits();
            auto *IntTy = IRB ? IRB->getIntNTy(Sz)
                              : Type::getIntNTy(DTy.getContext(), Sz);
            return IRB ? IRB->CreateIntToPtr(IRB->CreateFPToUI(V, IntTy), &DTy)
                       : ConstantExpr::getIntToPtr(
                             ConstantExpr::getFPToUI(cast<Constant>(V), IntTy),
                             &DTy);
        } else
            report_fatal_error("castToTy(): Unsupported floating-point cast!");
    } else if (STy.isIntegerTy()) {
        if (DTy.isFloatingPointTy())
            return IRB ? IRB->CreateUIToFP(V, &DTy)
                       : ConstantExpr::getUIToFP(cast<Constant>(V), &DTy);
        else if (DTy.isIntegerTy())
            // FIXME: isSigned = false
            return IRB ? IRB->CreateIntCast(V, &DTy, false)
                       : ConstantExpr::getIntegerCast(cast<Constant>(V), &DTy,
                                                      false);
        else if (DTy.isArrayTy() || DTy.isPointerTy())
            return IRB ? IRB->CreateIntToPtr(V, &DTy)
                       : ConstantExpr::getIntToPtr(cast<Constant>(V), &DTy);
        else
            report_fatal_error("castToTy(): Unsupported integer cast!");
    } else if (STy.isArrayTy() || STy.isPointerTy()) {
        if (DTy.isFloatingPointTy()) {
            const auto Sz = STy.getScalarSizeInBits();
            auto *IntTy = IRB ? IRB->getIntNTy(Sz)
                              : Type::getIntNTy(DTy.getContext(), Sz);
            return IRB ? IRB->CreateUIToFP(IRB->CreatePtrToInt(V, IntTy), &DTy)
                       : ConstantExpr::getUIToFP(ConstantExpr::getPtrToInt(
                                                     cast<Constant>(V), IntTy),
                                                 &DTy);
        } else if (DTy.isIntegerTy())
            return IRB ? IRB->CreatePtrToInt(V, &DTy)
                       : ConstantExpr::getPtrToInt(cast<Constant>(V), &DTy);
        else if (DTy.isArrayTy() || DTy.isPointerTy())
            return IRB ? IRB->CreatePointerCast(V, &DTy)
                       : ConstantExpr::getPointerCast(cast<Constant>(V), &DTy);
        else
            report_fatal_error(
                "castToTy(): Unsupported aggregate/pointer cast!");
    } else {
        errs() << "V: " << *V << ", ToTy: " << DTy << "\n";
        report_fatal_error("castToTy(): Unsupported cast!");
    }
}

bool isIntegerPointerPointerTy(const Type &Ty) {
    if (Ty.isPointerTy() && Ty.getPointerElementType()->isPointerTy())
        return Ty.getPointerElementType()
            ->getPointerElementType()
            ->isIntegerTy();
    return false;
}

bool isIntegerPointerTy(const Type &Ty) {
    return Ty.isPointerTy() && Ty.getPointerElementType()->isIntegerTy();
}

bool isStructPointerTy(const Type &Ty) {
    return Ty.isPointerTy() && Ty.getPointerElementType()->isStructTy();
}

bool isFunctionPointerTy(const Type &Ty, bool subTy) {
    if (subTy) {
        DedupVector<const Type *, 4> Stack;

        Stack.push_back(&Ty);
        while (!Stack.empty()) {
            const Type *T = Stack.pop_back_val();

            if (isFunctionPointerTy(*T, false))
                return true;
            for (Type *STy : T->subtypes())
                Stack.push_back(STy);
        }

        return false;
    }

    return Ty.isPointerTy() && Ty.getPointerElementType()->isFunctionTy();
}

bool isInt8PointerTy(const Type &Ty) {
    return Ty.isPointerTy() && Ty.getPointerElementType()->isIntegerTy(8);
}

/* C++ predicates */
const StringRef getPureVirtualName() { return "__cxa_pure_virtual"; }

const StringRef getDeletedVirtualName() { return "__cxa_deleted_virtual"; }

const StringRef getAllocateExceptionName() {
    return "__cxa_allocate_exception";
}

// FIXME: Brittle matching, modify/tag in Clang CodeGen instead
const Optional<std::string> getDemangledName(const StringRef Name) {
    const std::string Demangled = demangle(Name.str());
    return Demangled != Name ? Optional<std::string>(std::move(Demangled))
                             : Optional<std::string>();
}

bool isConstructor(const StringRef Name) {
    // Constructor returning void: <ctor-dtor-name>
    return Name.endswith("Ev") &&
           (Name.contains("C1") || Name.contains("C2") || Name.contains("C3") ||
            Name.contains("CI1") || Name.contains("CI2"));
}

// FIXME: Super hacky Itanium-specific ABI matching
bool isNonBaseConstructor(const StringRef Name) {
    return !Name.contains("C2E") &&
           (Name.contains("C1E") || Name.contains("C3E"));
}

bool isDestructor(const StringRef Name) {
    // Destructor returning void: <ctor-dtor-name>
    return Name.endswith("D0Ev") || Name.endswith("D1Ev") ||
           Name.endswith("D2Ev");
}

// FIXME: Super hacky Itanium-specific ABI matching
bool isNonBaseDestructor(const StringRef Name) {
    return !Name.contains("D2E") &&
           (Name.contains("D0E") || Name.contains("D1E"));
}

bool isTypeInfo(const std::string &Demangled) {
    return Demangled.rfind("typeinfo for ", 0) == 0;
}

bool isTypeInfoName(const std::string &Demangled) {
    return Demangled.rfind("typeinfo name for ", 0) == 0;
}

bool isVirtualThunk(const std::string &Demangled) {
    return Demangled.rfind("virtual thunk to ", 0) == 0;
}

bool isVTable(const std::string &Demangled) {
    return Demangled.find("vtable for ", 0) != std::string::npos;
}

bool isVTableTable(const std::string &Demangled) {
    return Demangled.rfind("VTT for ", 0) == 0;
}

bool isOperatorNew(const std::string &Demangled, bool *isArray) {
    if (isArray)
        *isArray = (Demangled.rfind("operator new[]") == 0);
    return Demangled.rfind("operator new") == 0;
}

bool isOperatorDelete(const std::string &Demangled, bool *isArray) {
    if (isArray)
        *isArray = (Demangled.rfind("operator delete[]") == 0);
    return Demangled.rfind("operator delete") == 0;
}

// FIXME: Brittle string matching, requires -fno-discard-value-names
bool isVTBaseOffsetVariable(const Value &V) {
    return V.getType()->isIntegerTy() && V.getName().startswith("vbase.offset");
}

// FIXME: Brittle string matching, requires -fno-discard-value-names
bool isVTableVariable(const Value &V) {
    return V.getType()->isPointerTy() && V.getName().startswith("vtable");
}

// FIXME: Brittle string matching, requires -fno-discard-value-names
bool isVTableTableVariable(const Value &V) {
    return isIntegerPointerPointerTy(*V.getType()) &&
           V.getName().startswith("vtt");
}

// FIXME: Brittle string matching, requires -fno-discard-value-names
bool isObjectPointerVariable(const Value &V) {
    return isStructPointerTy(*V.getType()) && V.getName().startswith("this");
}

/* System calls */
bool hasAsmSyscall(const std::string &s) {
    return s.find("syscall") != std::string::npos ||
           s.find("sysenter") != std::string::npos ||
           s.find("int $$0x80") != std::string::npos;
}

bool hasSyscall(const Value &V) {
    if (auto *IA = dyn_cast<InlineAsm>(&V))
        return hasAsmSyscall(IA->getAsmString());
    return false;
}

bool isHQSyscall(const Function &F) {
    return F.getName().startswith(STR(SYSCALL_RAW_FUNCTION));
}
