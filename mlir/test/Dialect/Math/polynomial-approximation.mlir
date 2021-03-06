// RUN: mlir-opt %s -test-math-polynomial-approximation | FileCheck %s

// Check that all math functions lowered to approximations built from
// standard operations (add, mul, fma, shift, etc...).

// CHECK-LABEL: @scalar
func @scalar(%arg0: f32) -> f32 {
  // CHECK-NOT: tanh
  %0 = math.tanh %arg0 : f32
  // CHECK-NOT: log
  %1 = math.log %0 : f32
  return %1 : f32
}

// CHECK-LABEL: @vector
func @vector(%arg0: vector<8xf32>) -> vector<8xf32> {
  // CHECK-NOT: tanh
  %0 = math.tanh %arg0 : vector<8xf32>
  // CHECK-NOT: log
  %1 = math.log %0 : vector<8xf32>
  return %1 : vector<8xf32>
}
