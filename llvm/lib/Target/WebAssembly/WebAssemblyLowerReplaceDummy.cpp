//===-- WebAssemblyLowerReplaceDummy.cpp - Replace Dummy --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is a dummy pass that replaces an instruction
///
//===----------------------------------------------------------------------===//

#include "MCTargetDesc/WebAssemblyMCTargetDesc.h"
#include "WebAssembly.h"
#include "WebAssemblyMachineFunctionInfo.h"
#include "WebAssemblySubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

#define DEBUG_TYPE "wasm-lower-replacedummy"

static cl::opt<bool> WasmDisableRodataCheck("tlmt-disable-rodata-check", cl::desc("disable rodata check for wasm"),
                                          cl::init(false), cl::Hidden);
static cl::opt<bool> WasmEnableAdditionalHeapCookies("tlmt-enable-additional-hc", cl::desc("enable additional heapcookies for wasm"),
                                          cl::init(false), cl::Hidden);                                          
                                          

namespace {
class WebAssemblyLowerReplaceDummy final : public MachineFunctionPass {
  StringRef getPassName() const override {
    return "WebAssembly Lower Replace Dummy";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

public:
  static char ID; // Pass identification, replacement for typeid
  WebAssemblyLowerReplaceDummy() : MachineFunctionPass(ID) {}
};
} // end anonymous namespace

char WebAssemblyLowerReplaceDummy::ID = 0;
INITIALIZE_PASS(WebAssemblyLowerReplaceDummy, DEBUG_TYPE,
                "Replacement Dummy", false, false)

FunctionPass *llvm::createWebAssemblyLowerReplaceDummy() {
  return new WebAssemblyLowerReplaceDummy();
}

// True if op is a store operation (doesnt support atomic, read-modify-write, and compare exchange ops from threads proposal)
bool isStoreOperation(unsigned opcode) {
switch (opcode) {
#define WASM_LOAD_STORE(NAME) \
  case WebAssembly::NAME##_A32: \
  case WebAssembly::NAME##_A64: \
  case WebAssembly::NAME##_A32_S: \
  case WebAssembly::NAME##_A64_S:
  WASM_LOAD_STORE(STORE8_I32)
  WASM_LOAD_STORE(STORE8_I64)
  WASM_LOAD_STORE(STORE16_I32)
  WASM_LOAD_STORE(STORE16_I64)
  WASM_LOAD_STORE(STORE_I32)
  WASM_LOAD_STORE(STORE_F32)
  WASM_LOAD_STORE(STORE32_I64)
  WASM_LOAD_STORE(STORE_I64)
  WASM_LOAD_STORE(STORE_F64)
    return 1;
  default:
    return 0;
  }
#undef WASM_LOAD_STORE
}

bool isOperationWeCanHandle(unsigned opcode) {
  switch (opcode) {
    case WebAssembly::LOCAL_GET_I32:
    case WebAssembly::GLOBAL_GET_I32:
    case WebAssembly::CONST_I32:
      return 1;
    default:
      return 0;
  }
}

/*
unsigned getLocalTypeForDataSet(unsigned opcode) {
	switch (opcode) {
		case WebAssembly::STORE_I32_A32:
		case WebAssembly::STORE8_I32_A32:
		case WebAssembly::STORE16_I32_A32:
		case WebAssembly::STORE_I32_A64:
		case WebAssembly::STORE8_I32_A64:
		case WebAssembly::STORE16_I32_A64:
			return WebAssembly::LOCAL_SET_I32;
		case WebAssembly::STORE_F32_A32:
		case WebAssembly::STORE_F32_A64:
			return WebAssembly::LOCAL_SET_F32;
		case WebAssembly::STORE_I64_A32:
		case WebAssembly::STORE8_I64_A32:
		case WebAssembly::STORE16_I64_A32:
		case WebAssembly::STORE32_I64_A32:
		case WebAssembly::STORE_I64_A64:
		case WebAssembly::STORE8_I64_A64:
		case WebAssembly::STORE16_I64_A64:
		case WebAssembly::STORE32_I64_A64:
			return WebAssembly::LOCAL_SET_I64;
		case WebAssembly::STORE_F64_A32:
		case WebAssembly::STORE_F64_A64:
			return WebAssembly::LOCAL_SET_F64;
		default:
			return WebAssembly::LOCAL_SET_I32;
	}
}

unsigned getLocalTypeForDataGet(unsigned opcode) {
	switch (opcode) {
		case WebAssembly::STORE_I32_A32:
		case WebAssembly::STORE8_I32_A32:
		case WebAssembly::STORE16_I32_A32:
		case WebAssembly::STORE_I32_A64:
		case WebAssembly::STORE8_I32_A64:
		case WebAssembly::STORE16_I32_A64:
			return WebAssembly::LOCAL_GET_I32;
		case WebAssembly::STORE_F32_A32:
		case WebAssembly::STORE_F32_A64:
			return WebAssembly::LOCAL_GET_F32;
		case WebAssembly::STORE_I64_A32:
		case WebAssembly::STORE8_I64_A32:
		case WebAssembly::STORE16_I64_A32:
		case WebAssembly::STORE32_I64_A32:
		case WebAssembly::STORE_I64_A64:
		case WebAssembly::STORE8_I64_A64:
		case WebAssembly::STORE16_I64_A64:
		case WebAssembly::STORE32_I64_A64:
			return WebAssembly::LOCAL_GET_I64;
		case WebAssembly::STORE_F64_A32:
		case WebAssembly::STORE_F64_A64:
			return WebAssembly::LOCAL_GET_F64;
		default:
			return WebAssembly::LOCAL_GET_I32;
	}
}
*/

bool WebAssemblyLowerReplaceDummy::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** Lowering Replacement Dummy **********\n"
                       "********** Function: "
                    << MF.getName() << '\n');

//  auto &MFI = *MF.getInfo<WebAssemblyFunctionInfo>();
  const auto &TII = *MF.getSubtarget<WebAssemblySubtarget>().getInstrInfo();
  auto &MRI = MF.getRegInfo();

  MachineFrameInfo &MFrameInfo = MF.getFrameInfo();
//  int stackObjectIdentifier = MFrameInfo.CreateStackObject(WebAssembly::SP32, Align(), false);
/*
  auto &FirstBlock = MF.front();
  auto insertPointer = FirstBlock.begin();
  while (insertPointer != FirstBlock.end() && WebAssembly::isArgument(insertPointer->getOpcode())) ++insertPointer;
*/
  DebugLoc DL;
/*
  errs() << MRI.getNumVirtRegs() << "\n";
  const TargetRegisterClass *PtrRC = MRI.getTargetRegisterInfo()->getPointerRegClass(MF);
  auto TestReg1 = MRI.createVirtualRegister(PtrRC);
  auto TestReg2 = MRI.createVirtualRegister(PtrRC);
  auto TestReg3 = MRI.createVirtualRegister(PtrRC);
  errs() << MRI.getNumVirtRegs() << "\n";
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::BLOCK))
  	.addImm(int64_t(WebAssembly::BlockType::Void));
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::CONST_I32), TestReg1)
        .addImm(10000);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::CONST_I32), TestReg2)
        .addImm(20);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::ADD_I32), TestReg3)
	 .addReg(TestReg1)
	 .addReg(TestReg2);
  auto TestReg4 = MRI.createVirtualRegister(PtrRC);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::GLOBAL_GET_I32), TestReg4)
        .addExternalSymbol(MF.createExternalSymbolName("__rodata_end"));
  auto TestReg5 = MRI.createVirtualRegister(PtrRC);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::GT_S_I32), TestReg5) // if sum > rodataEnd: put 1 on stack
	 .addReg(TestReg3)
	 .addReg(TestReg4);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::BR_IF)) // if 1 on stack, break out of block
  	 .addImm(0)
	 .addReg(TestReg5);
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::UNREACHABLE)); // trap!	 
  BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::END_BLOCK));
*/
//  errs() << "getNumObjects() " << MFrameInfo.getNumObjects() << "\n";
//  errs() << "estimateStackSize()" << MFrameInfo.estimateStackSize(MF) << "\n";
  if (MFrameInfo.hasStackProtectorIndex()) {  	
//  	errs() << "hasStackProtectorIndex(): " << MFrameInfo.hasStackProtectorIndex() << "\n";
  }
//  errs() << "FName:: " << MF.getName() << " " << WasmEnableAdditionalHeapCookies << "\n";
  
  // disable on init functions
  //  errs() << "getName(): " << Fn.getName() << "\n";
  if (MF.getName() == "__guard_setup" || MF.getName() == "initialize_malloc_heap")
  	return false;

  const TargetRegisterClass *PtrRC = MRI.getTargetRegisterInfo()->getPointerRegClass(MF);
  bool functionStores = 0;
  std::list<Register> taintedRegisters;
  std::list<int64_t> taintedLocals;
  bool stop = 0;
  for (auto &MBB : MF) {
//    errs() << "found mbb in " << MF.getName() << "\n";
    MachineInstr *MIsetsBase = nullptr;
    MachineInstr *MIprev = nullptr;
    MachineInstr *MI = nullptr;
    for (auto MII = MBB.begin(); MII != MBB.end();) {
      MIsetsBase = MIprev;
      MIprev = MI;
      MI = &*MII++;
      
      // Debug
//      MI->dump();
      // Find SP-Register
      if (MI->getOpcode() == WebAssembly::GLOBAL_GET_I32 && MI->getOperand(1).isSymbol() && !strcmp(MI->getOperand(1).getSymbolName(), "__stack_pointer")) {
//      	MI->dump();
      	taintedRegisters.push_front(MI->getOperand(0).getReg());
/*      	errs() << "getNumOperands(): " << MI->getNumOperands() << "\n";
      	errs() << "getOperand(0): " << MI->getOperand(0).getReg() << "\n";
      	errs() << "getOperand(1): " << MI->getOperand(1).getSymbolName() << "\n";
      	if (!strcmp(MI->getOperand(1).getSymbolName(), "__stack_pointer")) {
      		usedByGlobalGet = MI->getOperand(0).getReg();
      		taintedRegisters.push_front(MI->getOperand(0).getReg());
      	}
*/
      }
      // For all registers tainted by sp
      for (Register taintedRegister : taintedRegisters) {
      	if (MI->getOpcode() == WebAssembly::LOCAL_SET_I32 && MI->readsRegister(taintedRegister)) {    
//      		MI->dump();
      		taintedLocals.push_front(MI->getOperand(0).getImm()); // register saved to local
      	} 
      	else if (MI->getOpcode() == WebAssembly::SUB_I32 && MI->readsRegister(taintedRegister)) {
//      		MI->dump();
      		taintedRegisters.push_front(MI->getOperand(0).getReg()); // result in register
      	} 	
      }
      // Local loaded into register?
      if (MI->getOpcode() == WebAssembly::LOCAL_GET_I32) {
      	for (int64_t taintedLocal : taintedLocals) {
      		if (MI->getOperand(1).getImm() == taintedLocal) { // Local is tainted by sp?
//      			MI->dump();
      			taintedRegisters.push_front(MI->getOperand(0).getReg()); // register must be tainted as well
      		}
      	}
      }

      
/*      if (MI->readsRegister(usedByGlobalGet)) {
      	MI->dump();
      	errs() << "getNumOperands(): " << MI->getNumOperands() << "\n";
      	taintedLocals.push_front(MI->getOperand(0).getImm());
//      	errs() << "getOperand(1): " << MI->getOperand(1).getReg() << "\n";
//      	errs() << "readsRegister(): " << MI->readsRegister(usedByGlobalGet) << "\n";
//      	errs() << "readsVirtualRegister(): " << MI->readsVirtualRegister(usedByGlobalGet) << "\n";
      }
*/      
  
      
       // insert call to verify heap
      if (WasmEnableAdditionalHeapCookies && functionStores && MI->getOpcode() == WebAssembly::RETURN && // only when and where needed
      	!(MF.getName() == "export_validate_memory_regions" || MF.getName() == "validate_memory_regions" || MF.getName() == "_ZL23validate_memory_regionsv") && // prevent endless loops
      	(MF.getName() == "memcpy" || MF.getName() == "wmemcpy" || MF.getName() == "mempcpy" || MF.getName() == "wmempcpy" || // limit checks to string/array copy mechanics
      	MF.getName() == "memmove" || MF.getName() == "wmemmove" || MF.getName() == "memccpy" || 
      	MF.getName() == "memset" || MF.getName() == "wmemset" || MF.getName() == "strcpy" || MF.getName() == "wcscpy" ||
      	MF.getName() == "stpcpy" || MF.getName() == "wcpcpy" || MF.getName() == "bcopy" || MF.getName() == "bzero")
      	) { 
        auto CallReg = MRI.createVirtualRegister(PtrRC);
      	BuildMI(MBB, MI, DL, TII.get(WebAssembly::CALL), CallReg)
        	.addExternalSymbol(MF.createExternalSymbolName("export_validate_memory_regions"));
        errs() << "Adding memval into " << MF.getName() << "\n";
      }

      
      // Reset if call to prevent check-spam
      if (MI->getOpcode() == WebAssembly::CALL || MI->getOpcode() == WebAssembly::CALL_INDIRECT) {
      	functionStores = 0;
      	continue;
      }
      
      // Only continue if we actually have a store operation (why would we check if nothing was stored?)
      if (!isStoreOperation(MI->getOpcode()))
        continue;
        
      // Only continue, if its NOT something on the stack     
      for (Register taintedRegister : taintedRegisters) {
      	if(MI->getOperand(2).getReg() == taintedRegister) stop = 1;
      }
      if (stop) {
      	stop = 0;
      	continue;
      }
        
      functionStores = 1; // (better quality)
              
      // lets be sure, also skip weird code (dbg_value and selects where we lack info)
      if (!MIsetsBase || !isOperationWeCanHandle(MIsetsBase->getOpcode()) || !isOperationWeCanHandle(MIprev->getOpcode()))
        continue;
        
      // If offset is not a number, we want the base to be zero 
      if (!MI->getOperand(1).isImm() && !(MIsetsBase->getOperand(1).isImm() && MIsetsBase->getOperand(1).getImm() == 0))
        continue;



/*      MIsetsBase->dump();
      MIprev->dump();
      MI->dump();
      //errs() << "getNumOperands(): " << MI->getNumOperands() << "\n";
      errs() << "Base: " << MIsetsBase->getOperand(1) << "\n";
      errs() << "Offset: " << MI->getOperand(1) << "\n";
*/     

      // Only do stuff, if requested
      if (WasmDisableRodataCheck)
        continue;
      errs() << "Found relevant store op in " << MF.getName() << "\n";
        
      auto TestReg1 = MRI.createVirtualRegister(PtrRC);
      auto TestReg2 = MRI.createVirtualRegister(PtrRC);
      auto TestReg3 = MRI.createVirtualRegister(PtrRC);
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::BLOCK))
	.addImm(int64_t(WebAssembly::BlockType::Void));
      if (MI->getOperand(1).isImm()) {
        BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::CONST_I32), TestReg1) // Offset
        	.addImm(MI->getOperand(1).getImm());
        BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::LOCAL_GET_I32), TestReg2) // Base
        	.addImm(MIsetsBase->getOperand(1).getImm());
        BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::ADD_I32), TestReg3)
		.addReg(TestReg1)
		.addReg(TestReg2);
      }
      else {
      	BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::CONST_I32), TestReg3) // Offset
      		.add(MI->getOperand(1)); // probably a symbol
      }
      auto TestReg4 = MRI.createVirtualRegister(PtrRC);
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::GLOBAL_GET_I32), TestReg4)
        .addExternalSymbol(MF.createExternalSymbolName("__rodata_end"));
      auto TestReg5 = MRI.createVirtualRegister(PtrRC);
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::GT_S_I32), TestReg5) // if sum > rodataEnd: put 1 on stack
	 .addReg(TestReg3)
	 .addReg(TestReg4);
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::BR_IF)) // if 1 on stack, break out of block
  	 .addImm(0)
	 .addReg(TestReg5);
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::UNREACHABLE)); // trap!	 
      BuildMI(MBB, MIsetsBase, DL, TII.get(WebAssembly::END_BLOCK));
     

     //MI->setDesc(TII.get(WebAssembly::SUB_I32));
     // Put Offset on Stack
//     auto TestReg = MRI.createVirtualRegister(MRI.getTargetRegisterInfo()->getPointerRegClass(MF));
//     BuildMI(FirstBlock, insertPointer, DL, TII.get(WebAssembly::CONST_I32), TestReg)
//		.addImm(MI->getOperand(1));
     // Put Address on Stack
//     auto TestRegZ = MRI.createVirtualRegister(MRI.getTargetRegisterInfo()->getPointerRegClass(MF));
     		

    }
  }

  return false;
}
