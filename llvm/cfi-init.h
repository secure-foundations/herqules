#ifndef _CFI_LLVM_INIT_H_
#define _CFI_LLVM_INIT_H_

#include "llvm/Support/CommandLine.h"

#include <string>

// Shared configuration flags
extern llvm::cl::opt<bool> CFIDominatorAnalysis, LibraryFunctions, RunCFI,
    UseStrictFP;

extern llvm::cl::opt<std::string> InlinePath;

#endif /* _CFI_LLVM_INIT_H_ */
