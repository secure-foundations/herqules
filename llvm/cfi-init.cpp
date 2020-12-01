#include <llvm/PassRegistry.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include "cfi-finalize.h"
#include "cfi-init.h"
#include "cfi-instrument.h"
#include "hq-syscall.h"
#include "utils.h"

using namespace llvm;

static constexpr char TEST_PLUGIN_NAME[] = "CFI Passes";
static constexpr char TEST_PLUGIN_VERSION[] = "1.0";

// FIXME: Checks an environment variable, because LTO driver will not pass LLVM
// command-line arguments, and LTO plugin will not parse them
cl::opt<std::string> InlinePath(
    "hq-inline-path",
    cl::desc("Path to bitcode implementation of the interface's messaging "
             "functions, which will be inlined after optimization, if "
             "provided. (default = <empty>, or HQ_INLINE_PATH)"),
    cl::value_desc("path"));

// Shared configuration flags

cl::opt<bool>
    CFIDominatorAnalysis("cfi-dominator-analysis",
                         cl::desc("Use dominator analysis results to elide "
                                  "pointer messages (default = true)"),
                         cl::init(true));
cl::opt<bool>
    RedirectFunctions("cfi-redirect-functions",
                      cl::desc("Redirect free/mempcy/memmove/realloc to "
                               "instrumented wrappers (default = true)"),
                      cl::init(true));

cl::opt<bool> RunCFI("run-cfi",
                     cl::desc("Enable CFI instrumentation (default = true)"),
                     cl::init(true));

cl::opt<bool> UseStrictFP(
    "cfi-strict-fp",
    cl::desc("Use strict subtype matching for function pointer detection that "
             "doesn't whitelist generic pointers (default = true)"),
    cl::init(true));

// Use static object to initialize passes when the plugin is loaded, so that
// they are available in 'opt'. Based on Polly.cpp/RegisterPasses.cpp.
class StaticInitializer {
    static void initializeCFIPasses(PassRegistry &PR) {
        initializeCFIInstrumentLegacyPassPass(PR);
        initializeCFIFinalizeLegacyPassPass(PR);
        initializeHQSyscallLegacyPassPass(PR);
    }

  public:
    StaticInitializer() {
        PassRegistry &PR = *PassRegistry::getPassRegistry();
        initializeCFIPasses(PR);

        // FIXME: Checks an environment variable, because Clang `cc1as` driver
        // does not load LLVM passes, which will break compilation on assembly
        // files due to unrecognized `-mllvm -cfi-syscalls-only=true` argument
        if (getSysCallsOnly()) {
            outs() << "Only instrumenting system calls, disabling all other "
                      "instrumentation!\n";
            RunCFI = false;
            RunCFIRetAddr = false;
            RunSysCalls = true;
        }
    }
};

static StaticInitializer Initializer;

extern "C" PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, TEST_PLUGIN_NAME, TEST_PLUGIN_VERSION,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
                    if (Name.equals("cfi-finalize")) {
                        CFIFinalizePass::create(MPM);
                        return true;
                    } else if (Name.equals("cfi-instrument")) {
                        CFIInstrumentPass::create(MPM);
                        return true;
                    } else if (Name.equals("hq-syscall")) {
                        HQSyscallPass::create(MPM);
                        return true;
                    }

                    return false;
                });

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM) { CFIInstrumentPass::create(MPM); });

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM) { HQSyscallPass::create(MPM); });

            // FIXME: Need to run finalize pass at OptimizerLastEPCallback,
            // but new pass manager doesn't support a ModulePass there
            PB.registerOptimizerLastEPCallback(
                [](FunctionPassManager &FPM,
                   PassBuilder::OptimizationLevel Level) {
                    report_fatal_error(
                        "No suitable callbacks for CFI finalization pass with "
                        "new pass manager!");
                });

            // FIXME: Need to run instrument and finalize pass at LTO
            // callback, but new pass manager doesn't have LTO callbacks
        }};
}
