; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -slp-vectorizer -S 2>%t | FileCheck %s
; RUN: FileCheck --check-prefix=WARN --allow-empty %s <%t

; WARN-NOT: warning

target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-unknown-linux-gnu"

; This test check that we are not crashing or changing the code.

define void @test() {
; CHECK-LABEL: @test(
; CHECK-NEXT:    [[LOAD0:%.*]] = tail call <vscale x 16 x i8> @llvm.masked.load.nxv16i8.p0nxv16i8(<vscale x 16 x i8>* undef, i32 1, <vscale x 16 x i1> undef, <vscale x 16 x i8> undef)
; CHECK-NEXT:    [[LOAD1:%.*]] = tail call <vscale x 16 x i8> @llvm.masked.load.nxv16i8.p0nxv16i8(<vscale x 16 x i8>* undef, i32 1, <vscale x 16 x i1> undef, <vscale x 16 x i8> undef)
; CHECK-NEXT:    [[ADD:%.*]] = add <vscale x 16 x i8> [[LOAD1]], [[LOAD0]]
; CHECK-NEXT:    tail call void @llvm.masked.store.nxv16i8.p0nxv16i8(<vscale x 16 x i8> [[ADD]], <vscale x 16 x i8>* undef, i32 1, <vscale x 16 x i1> undef)
; CHECK-NEXT:    ret void
;
  %load0 = tail call <vscale x 16 x i8> @llvm.masked.load.nxv16i8.p0nxv16i8(<vscale x 16 x i8> *undef, i32 1, <vscale x 16 x i1> undef, <vscale x 16 x i8> undef)
  %load1 = tail call <vscale x 16 x i8> @llvm.masked.load.nxv16i8.p0nxv16i8(<vscale x 16 x i8> *undef, i32 1, <vscale x 16 x i1> undef, <vscale x 16 x i8> undef)
  %add = add <vscale x 16 x i8> %load1, %load0
  tail call void @llvm.masked.store.nxv16i8.p0nxv16i8(<vscale x 16 x i8> %add, <vscale x 16 x i8>* undef, i32 1, <vscale x 16 x i1> undef)
  ret void
}

define <vscale x 4 x i32> @scalable_phi(<vscale x 4 x i32> %a, i32 %b) {
; CHECK-LABEL: @scalable_phi(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[CMP:%.*]] = icmp eq i32 [[B:%.*]], 0
; CHECK-NEXT:    br i1 [[CMP]], label [[IF_THEN:%.*]], label [[END:%.*]]
; CHECK:       if.then:
; CHECK-NEXT:    br label [[END]]
; CHECK:       end:
; CHECK-NEXT:    [[RETVAL:%.*]] = phi <vscale x 4 x i32> [ [[A:%.*]], [[ENTRY:%.*]] ], [ zeroinitializer, [[IF_THEN]] ]
; CHECK-NEXT:    ret <vscale x 4 x i32> [[RETVAL]]
;
entry:
  %cmp = icmp eq i32 %b, 0
  br i1 %cmp, label %if.then, label %end

if.then:
  br label %end

end:
  %retval = phi <vscale x 4 x i32> [ %a, %entry ], [ zeroinitializer, %if.then ]
  ret <vscale x 4 x i32> %retval
}

declare <vscale x 16 x i8> @llvm.masked.load.nxv16i8.p0nxv16i8(<vscale x 16 x i8>*, i32 immarg, <vscale x 16 x i1>, <vscale x 16 x i8>)
declare void @llvm.masked.store.nxv16i8.p0nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>*, i32 immarg, <vscale x 16 x i1>)
