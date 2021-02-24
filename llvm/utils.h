#ifndef _HQ_LLVM_UTILS_H_
#define _HQ_LLVM_UTILS_H_

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <unordered_map>
#include <utility>

using namespace llvm;

/* Deduplicated vector */
// Similar to SetVector, but never removes items from the underlying set
template <typename T, unsigned N> class DedupVector {
    SmallSet<T, N> s;
    SmallVector<T, N> v;

  public:
    bool empty() const { return v.empty(); }

    T pop_back_val() { return v.pop_back_val(); }

    bool push_back(const T &x) {
        bool ret = s.insert(x).second;
        if (ret)
            v.push_back(x);
        return ret;
    }

    void clear() {
        s.clear();
        v.clear();
    }
};

/* Memory function types */
// Similar to MemoryBuiltins::AllocType
typedef enum {
    Unknown,
    Malloc,
    Calloc,
    Realloc,
    OpNew,
    Free,
    MemCpy,
    MemMove,
} MemFnType;

/* Call paths */
template <typename T1, typename T2> struct std::hash<std::pair<T1, T2>> {
    std::size_t operator()(const std::pair<T1, T2> &p) const {
        return std::hash<T1>()(p.first) ^ std::hash<T2>()(p.second);
    }
};

/* IntToPtr helper */
class IntToPtrOperator
    : public ConcreteOperator<Operator, Instruction::IntToPtr> {
    friend class IntToPtr;
    friend class ConstantExpr;

  public:
    Value *getValueOperand() { return getOperand(0); }
    const Value *getValueOperand() const { return getOperand(0); }

    static unsigned getValueOperandIndex() {
        return 0U; // get index for modifying correct operand
    }

    /// Method to return the pointer operand as a PointerType.
    Type *getValueOperandType() const { return getValueOperand()->getType(); }
};

/* Utility functions */
// Create a CallInst with type casts on input arguments if necessary.
// Does not modify the IRBuilder insertion point before creating instructions.
CallInst *createCastedCall(IRBuilder<> &IRB, FunctionCallee &FC,
                           MutableArrayRef<Value *> Args);

// Create HQ functions.
void createHQFunctions(IRBuilder<> &IRB, Module &M, FunctionCallee *PCF,
                       FunctionCallee *PCIF, FunctionCallee *PDF,
                       FunctionCallee *PIF, FunctionCallee *SCF,
                       FunctionCallee *PMCF, FunctionCallee *PFF,
                       FunctionCallee *PRF);

// Create system call instrumentation.
bool createSyscallMessage(IRBuilder<> &IRB, CallBase &CB, FunctionCallee &SCF,
                          const DominatorTree *DT,
                          const PostDominatorTree *PDT);

// Create global instrumentation at program startup
void createGlobalInit(Module &M,
                      const SmallVectorImpl<Constant *> &InitGlobalsInternal,
                      const SmallVectorImpl<Constant *> &InitGlobalsExternal);

// Identify global variables with sensitive pointers. STy is the type of the
// two-field struct used to track each pointer-value pair.
void instrumentGlobalVariables(
    Module &M, StructType &STy, bool LTO, const ArrayRef<const Value *> Exclude,
    SmallVectorImpl<Constant *> &InitGlobalsInternal,
    SmallVectorImpl<Constant *> &InitGlobalsExternal);

// Resolve the target of a GetElementPtr, given constant indices. If argument
// is true, attempt to resolve through the initializer given constant indices.
const Value *resolveGEP(const GEPOperator *GEP, bool initGEP = true);

// Simplify an instruction, removing casts, GEPs, invariant groups, etc.
// First argument is passed through to resolveGEP, second one is used to skip
// over GEPs completely.
const Value *simplify(const Value *V, bool initGEP = true,
                      bool skipGEP = false);

// Return whether two values are equivalent, ignoring casts
bool isEquivalent(const Value *V1, const Value *V2);

// Find first insertion point after AllocaInsts
Instruction *getFirstNonAllocaInsertionPt(BasicBlock &BB);

// Fetch and parse environment variable to determine syscalls only mode
bool getSysCallsOnly();

// Fetch and parse environment variable to determine inline interface path
const Optional<std::string> getInlinePath();

// Perform inlining using given path if valid, otherwise fetch path
bool performInlining(Module &M, const cl::opt<std::string> &Path);

// Determine if this is a SPEC benchmark that does not support strict function
// pointer identifications, given the module and function names
MemFnType getSPECNoStrictFP(const StringRef MName, const StringRef FName);

// Returns whether the call is a HQ function
bool isHQFunction(const Function &F);

// Returns whether the call is a CFI pointer function
bool isCFIPointerFunction(const Function &F);

// Returns whether the variable is a C string
bool isCString(const Value &V);

// Recursively visit a value and check if it is a function pointer. If subTy
// is true, also check whether the value's subtypes include function pointers.
bool isFunctionPointer(const Value &V, bool strictFP, bool subTy = false);

/* Type predicates */
// Cast a value to a type
Value *castToTy(IRBuilder<> *IRB, Value *C, Type &DTy);

// Determine if a type is a pointer to a pointer to an integer
bool isIntegerPointerPointerTy(const Type &Ty);

// Determine if a type is a pointer to an integer
bool isIntegerPointerTy(const Type &Ty);

// Determine if a type is a pointer to a struct
bool isStructPointerTy(const Type &Ty);

// Determine if a type is a pointer to a function. If subTy is true, also check
// whether the type's subtypes include function pointers.
bool isFunctionPointerTy(const Type &Ty, bool subTy = false);

// Determine if a type is a pointer to an 8-bit integer (void *)
bool isInt8PointerTy(const Type &Ty);

/* C++ predicates */
// Get the name of the C++ pure virtual error handler
const StringRef getPureVirtualName();

// Get the name of the C++ deleted virtual error handler
const StringRef getDeletedVirtualName();

// Get the name of the C++ allocation function for exceptions
const StringRef getAllocateExceptionName();

// Get the optional demangled C++ symbol name from a string
const Optional<std::string> getDemangledName(const StringRef Name);

// Determine if a C++ symbol is a constructor
bool isConstructor(const StringRef Name);

// Determine if a C++ constructor is complete
bool isNonBaseConstructor(const StringRef Name);

// Determine if a C++ symbol is a destructor
bool isDestructor(const StringRef Name);

// Determine if a C++ destructor is complete or deleting
bool isNonBaseDestructor(const StringRef Name);

// Determine if a demangled C++ symbol is a typeinfo
bool isTypeInfo(const std::string &Demangled);

// Determine if a demangled C++ symbol is a typeinfo name
bool isTypeInfoName(const std::string &Demangled);

// Determine if a demangled C++ symbol is a virtual thunk
bool isVirtualThunk(const std::string &Demangled);

// Determine if a demangled C++ symbol is a vtable
bool isVTable(const std::string &Demangled);

// Determine if a demangled C++ symbol is a vtable table
bool isVTableTable(const std::string &Demangled);

// Determine if a demangled C++ symbol is operator new
bool isOperatorNew(const std::string &Demangled, bool *isArray = nullptr);

// Determine if a demangled C++ symbol is operator delete
bool isOperatorDelete(const std::string &Demangled, bool *isArray = nullptr);

// Determine if an instruction computes the C++ 'vbase.offset' vtable base
// offset
bool isVTBaseOffsetVariable(const Value &V);

// Determine if an instruction computes the C++ 'vtable' vtable pointer
bool isVTableVariable(const Value &V);

// Determine if an instruction computes the C++ 'vtt' vtable table pointer
bool isVTableTableVariable(const Value &V);

// Determine if an instruction computes the C++ 'this' object pointer
bool isObjectPointerVariable(const Value &V);

/* System calls */
// Determine if an assembly string contains a system call
bool hasAsmSyscall(const std::string &s);

// Determine if an instruction performs a direct system call
bool hasSyscall(const Value &V);

// Determine if a function is the non-instrumented internal system call
// function
bool isHQSyscall(const Function &F);

#endif /* _HQ_LLVM_UTILS_H_ */
