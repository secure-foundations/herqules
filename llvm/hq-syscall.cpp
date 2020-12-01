#include "llvm/ADT/Statistic.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#ifndef NDEBUG
#include "llvm/IR/Verifier.h"
#endif

#include "config.h"

#include "hq-syscall.h"
#include "utils.h"

#define DEBUG_TYPE "hq-syscall"

using namespace llvm;

cl::opt<bool> RunSysCalls(
    "run-hq-syscalls",
    cl::desc(
        "Enable HerQules instrumentation for system calls (default = true)"),
    cl::init(true));

static cl::opt<bool>
    UseDominatorAnalysis("hq-dominator-analysis",
                         cl::desc("Use dominator analysis results to move "
                                  "system call checks (default = true)"),
                         cl::init(true));

// Ensure statistics are defined even in release mode
#if !defined(NDEBUG) || defined(LLVM_ENABLE_STATS)
STATISTIC(NumSysCall, "Number of instrumented system calls");
#else
static unsigned int NumSysCall = 0;
#endif /* !NDEBUG || LLVM_ENABLE_STATS */

/* Types */
using DominatorCallbacks =
    function_ref<std::pair<DominatorTree *, PostDominatorTree *>(Function &F)>;

/* Visitor for modifying instructions */
struct SyscallVisitor : public InstVisitor<SyscallVisitor> {
    const DataLayout *DL;
    IRBuilder<> IRB;
    DominatorCallbacks &DCB;
    FunctionCallee SCF;

    /* Information about current function */
    Function *currentFunc;
    DominatorTree *DT;
    PostDominatorTree *PDT;

    SyscallVisitor(LLVMContext &C, DominatorCallbacks &_DCB)
        : IRB(C), DCB(_DCB) {}

    void visit(Module &M) {
        visitModule(M);
        InstVisitor::visit(M.begin(), M.end());
    }

    void visit(Function &F) {
        if (F.isDeclaration())
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
        if (hasAsmSyscall(M.getModuleInlineAsm())) {
            errs() << M.getModuleInlineAsm() << "\n";
            report_fatal_error("System call within module-level inline "
                               "assembly not supported!");
        }

        createHQFunctions(IRB, M, nullptr, nullptr, nullptr, nullptr, &SCF,
                          nullptr, nullptr, nullptr, nullptr);
    }

    void visitFunction(Function &F) {
        currentFunc = &F;
        std::tie(DT, PDT) = DCB(F);
    }

    void visitCallBase(CallBase &CB) {
        Value *V = CB.getCalledOperand();

        if (hasSyscall(*V) && !isHQSyscall(*currentFunc)) {
            if (currentFunc->hasFnAttribute(Attribute::AlwaysInline)) {
                // If this system call is inlinable, send the system call
                // message before each call site of the current function
                for (auto *U : currentFunc->users()) {
                    if (auto *UCB = dyn_cast<CallBase>(U)) {
                        const DominatorTree *ParentDT;
                        const PostDominatorTree *ParentPDT;
                        // Fetch the dominator tree and post-dominator tree for
                        // the caller
                        std::tie(ParentDT, ParentPDT) =
                            DCB(*UCB->getFunction());

                        if (!createSyscallMessage(IRB, *UCB, SCF, DT, PDT))
                            report_fatal_error(
                                "Unable to create system call message!");
                        ++NumSysCall;
                    }
                }
            } else {
                // Otherwise, send it in the current function
                if (!createSyscallMessage(IRB, CB, SCF, DT, PDT))
                    report_fatal_error("Unable to create system call message!");
                ++NumSysCall;
            }
        }
    }
};

/* Create HQ instrumentation */
static bool createHQSyscalls(Module &M, DominatorCallbacks DCB) {
    if (!RunSysCalls)
        return false;

#ifdef HQ_CHECK_SYSCALL
    LLVMContext &C = M.getContext();
    SyscallVisitor SV(C, DCB);
    SV.visit(M);
#endif /* HQ_CHECK_SYSCALL */

    if (NumSysCall)
        outs() << M.getName() << ": Instrumented " << NumSysCall
               << " system calls\n";
    return NumSysCall;
}

/* Implementation for legacy pass manager */
void HQSyscallLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
    if (UseDominatorAnalysis) {
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }

    AU.setPreservesCFG();
}

bool HQSyscallLegacyPass::runOnModule(Module &M) {
    auto DCB =
        [this](Function &F) -> std::pair<DominatorTree *, PostDominatorTree *> {
        return UseDominatorAnalysis && !F.isDeclaration()
                   ? std::make_pair<>(
                         &this->getAnalysis<DominatorTreeWrapperPass>(F)
                              .getDomTree(),
                         &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                              .getPostDomTree())
                   : std::make_pair<>(nullptr, nullptr);
    };

    return createHQSyscalls(M, DCB);
}

char HQSyscallLegacyPass::ID = 0;

// Use this because RegisterPass<...>(...) does not support dependent passes
INITIALIZE_PASS_BEGIN(HQSyscallLegacyPass, DEBUG_TYPE, "HQ Syscall Pass", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(HQSyscallLegacyPass, DEBUG_TYPE, "HQ Syscall Pass", false,
                    false)

static void RegisterLegacyPasses(const PassManagerBuilder &Builder,
                                 legacy::PassManagerBase &PM) {
    PassRegistry *PR = PassRegistry::getPassRegistry();

    initializeHQSyscallLegacyPassPass(*PR);
    PM.add(new HQSyscallLegacyPass());
#ifndef NDEBUG
    PM.add(createVerifierPass());
#endif /* NDEBUG */
}

static RegisterStandardPasses HQSyscallRegisterLast(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        RegisterLegacyPasses(Builder, PM);
    });

static RegisterStandardPasses HQSyscallRegisterL0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        RegisterLegacyPasses(Builder, PM);
    });

/* Implementation for new pass manager */
void HQSyscallPass::create(ModulePassManager &MPM) {
    if (UseDominatorAnalysis) {
        MPM.addPass(RequireAnalysisPass<DominatorTreeAnalysis, Module>());
        MPM.addPass(RequireAnalysisPass<PostDominatorTreeAnalysis, Module>());
    }

    MPM.addPass(HQSyscallPass());
#ifndef NDEBUG
    MPM.addPass(VerifierPass());
#endif /* NDEBUG */
}

PreservedAnalyses HQSyscallPass::run(Module &M, ModuleAnalysisManager &MAM) {
    PassBuilder PB;
    PB.registerModuleAnalyses(MAM);
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

    auto DCB =
        [&FAM](Function &F) -> std::pair<DominatorTree *, PostDominatorTree *> {
        return UseDominatorAnalysis && !F.isDeclaration()
                   ? std::make_pair<>(
                         &FAM.getResult<DominatorTreeAnalysis>(F),
                         &FAM.getResult<PostDominatorTreeAnalysis>(F))
                   : std::make_pair<>(nullptr, nullptr);
    };

    createHQSyscalls(M, DCB);
    return PreservedAnalyses::all();
}

#undef DEBUG_TYPE
