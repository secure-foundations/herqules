#ifndef _HQ_LLVM_SYSCALL_H_
#define _HQ_LLVM_SYSCALL_H_

#include "llvm/IR/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"

#include "config.h"

extern llvm::cl::opt<bool> RunSysCalls;

namespace llvm {
void initializeHQSyscallLegacyPassPass(PassRegistry &);

struct HQSyscallLegacyPass : public ModulePass {
    static char ID;

    HQSyscallLegacyPass() : ModulePass(ID) {}
    void getAnalysisUsage(AnalysisUsage &AU) const override;
    bool runOnModule(Module &M) override;
}; // end of struct HQSyscallLegacyPass

struct HQSyscallPass : public PassInfoMixin<HQSyscallPass> {
    HQSyscallPass() {}
    static void create(ModulePassManager &MPM);
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
}; // end of struct HQSyscallPass
}; // namespace llvm

#endif /* _HQ_LLVM_SYSCALL_H_ */
