#ifndef _CFI_LLVM_CFI_FINALIZE_H_
#define _CFI_LLVM_CFI_FINALIZE_H_

#include "llvm/IR/PassManager.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"

#include "config.h"

extern llvm::cl::opt<bool> RunCFIRetAddr;

namespace llvm {
void initializeCFIFinalizeLegacyPassPass(PassRegistry &);

struct CFIFinalizeLegacyPass : public ModulePass {
    static char ID;

    CFIFinalizeLegacyPass() : ModulePass(ID) {}
    void getAnalysisUsage(AnalysisUsage &AU) const override;
    bool runOnModule(Module &M) override;
}; // end of struct CFIFinalizeLegacyPass

struct CFIFinalizePass : public PassInfoMixin<CFIFinalizePass> {
  public:
    static void create(ModulePassManager &MPM);
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
}; // end of struct CFIFinalizePass
}; // namespace llvm

#endif /* _CFI_LLVM_CFI_FINALIZE_H_ */
