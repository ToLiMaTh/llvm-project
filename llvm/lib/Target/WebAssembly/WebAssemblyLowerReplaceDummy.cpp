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
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

#define DEBUG_TYPE "wasm-lower-replacedummy"

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

bool WebAssemblyLowerReplaceDummy::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "********** Lowering Replacement Dummy **********\n"
                       "********** Function: "
                    << MF.getName() << '\n');

  auto &MFI = *MF.getInfo<WebAssemblyFunctionInfo>();
  const auto &TII = *MF.getSubtarget<WebAssemblySubtarget>().getInstrInfo();
  auto &MRI = MF.getRegInfo();

  for (auto &MBB : MF) {
    for (auto MII = MBB.begin(); MII != MBB.end();) {
      MachineInstr *MI = &*MII++;
      if (MI->getOpcode() != WebAssembly::MUL_I32)
        continue;


     errs() << "Found a MUL_I32! (change22) " << MI << "\n";

     MI->setDesc(TII.get(WebAssembly::SUB_I32));


    }
  }

  return false;
}
