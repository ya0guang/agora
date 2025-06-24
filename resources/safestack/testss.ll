; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline nounwind optnone safestack uwtable
define dso_local i32 @test_args(i32 noundef %arg1, i32 noundef %arg2, i32 noundef %arg3) #0 {
entry:
  %arg1.addr = alloca i32, align 4
  %arg2.addr = alloca i32, align 4
  %arg3.addr = alloca i32, align 4
  %r = alloca i32, align 4
  store i32 %arg1, ptr %arg1.addr, align 4
  store i32 %arg2, ptr %arg2.addr, align 4
  store i32 %arg3, ptr %arg3.addr, align 4
  %0 = load i32, ptr %arg1.addr, align 4
  %1 = load i32, ptr %arg2.addr, align 4
  %add = add nsw i32 %0, %1
  %2 = load i32, ptr %arg3.addr, align 4
  %add1 = add nsw i32 %add, %2
  store i32 %add1, ptr %r, align 4
  %3 = load i32, ptr %r, align 4
  ret i32 %3
}

; Function Attrs: noinline nounwind optnone safestack uwtable
define dso_local i32 @test_array1() #0 {
entry:
  %a = alloca [100 x i32], align 16
  %i = alloca i32, align 4
  store i32 0, ptr %i, align 4
  br label %for.cond

for.cond:                                         ; preds = %for.inc, %entry
  %0 = load i32, ptr %i, align 4
  %cmp = icmp slt i32 %0, 100
  br i1 %cmp, label %for.body, label %for.end

for.body:                                         ; preds = %for.cond
  %1 = load i32, ptr %i, align 4
  %2 = load i32, ptr %i, align 4
  %idxprom = sext i32 %2 to i64
  %arrayidx = getelementptr inbounds [100 x i32], ptr %a, i64 0, i64 %idxprom
  store i32 %1, ptr %arrayidx, align 4
  br label %for.inc

for.inc:                                          ; preds = %for.body
  %3 = load i32, ptr %i, align 4
  %inc = add nsw i32 %3, 1
  store i32 %inc, ptr %i, align 4
  br label %for.cond, !llvm.loop !6

for.end:                                          ; preds = %for.cond
  %arrayidx1 = getelementptr inbounds [100 x i32], ptr %a, i64 0, i64 99
  %4 = load i32, ptr %arrayidx1, align 4
  ret i32 %4
}

; Function Attrs: noinline nounwind optnone safestack uwtable
define dso_local i32 @test_array2(i32 noundef %size) #0 {
entry:
  %size.addr = alloca i32, align 4
  %saved_stack = alloca ptr, align 8
  %__vla_expr0 = alloca i64, align 8
  %i = alloca i32, align 4
  store i32 %size, ptr %size.addr, align 4
  %0 = load i32, ptr %size.addr, align 4
  %1 = zext i32 %0 to i64
  %2 = call ptr @llvm.stacksave()
  store ptr %2, ptr %saved_stack, align 8
  %vla = alloca i32, i64 %1, align 16
  store i64 %1, ptr %__vla_expr0, align 8
  store i32 0, ptr %i, align 4
  br label %for.cond

for.cond:                                         ; preds = %for.inc, %entry
  %3 = load i32, ptr %i, align 4
  %4 = load i32, ptr %size.addr, align 4
  %cmp = icmp slt i32 %3, %4
  br i1 %cmp, label %for.body, label %for.end

for.body:                                         ; preds = %for.cond
  %5 = load i32, ptr %i, align 4
  %6 = load i32, ptr %i, align 4
  %idxprom = sext i32 %6 to i64
  %arrayidx = getelementptr inbounds i32, ptr %vla, i64 %idxprom
  store i32 %5, ptr %arrayidx, align 4
  br label %for.inc

for.inc:                                          ; preds = %for.body
  %7 = load i32, ptr %i, align 4
  %inc = add nsw i32 %7, 1
  store i32 %inc, ptr %i, align 4
  br label %for.cond, !llvm.loop !8

for.end:                                          ; preds = %for.cond
  %8 = load i32, ptr %size.addr, align 4
  %sub = sub nsw i32 %8, 1
  %idxprom1 = sext i32 %sub to i64
  %arrayidx2 = getelementptr inbounds i32, ptr %vla, i64 %idxprom1
  %9 = load i32, ptr %arrayidx2, align 4
  %10 = load ptr, ptr %saved_stack, align 8
  call void @llvm.stackrestore(ptr %10)
  ret i32 %9
}

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare ptr @llvm.stacksave() #1

; Function Attrs: nocallback nofree nosync nounwind willreturn
declare void @llvm.stackrestore(ptr) #1

; Function Attrs: noinline nounwind optnone safestack uwtable
define dso_local i32 @main(i32 noundef %argc, ptr noundef %argv) #0 {
entry:
  %argc.addr = alloca i32, align 4
  %argv.addr = alloca ptr, align 8
  %arg1 = alloca i32, align 4
  %arg2 = alloca i32, align 4
  %arg3 = alloca i32, align 4
  %r = alloca i32, align 4
  store i32 %argc, ptr %argc.addr, align 4
  store ptr %argv, ptr %argv.addr, align 8
  store i32 1, ptr %arg1, align 4
  store i32 2, ptr %arg2, align 4
  store i32 3, ptr %arg3, align 4
  %0 = load i32, ptr %arg1, align 4
  %1 = load i32, ptr %arg2, align 4
  %2 = load i32, ptr %arg3, align 4
  %call = call i32 @test_args(i32 noundef %0, i32 noundef %1, i32 noundef %2)
  store i32 %call, ptr %r, align 4
  %call1 = call i32 @test_array1()
  store i32 %call1, ptr %r, align 4
  %3 = load i32, ptr %r, align 4
  %call2 = call i32 @test_array2(i32 noundef %3)
  store i32 %call2, ptr %r, align 4
  ret i32 0
}

attributes #0 = { noinline nounwind optnone safestack uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind willreturn }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 15.0.7 (https://github.com/llvm/llvm-project 8dfdcc7b7bf66834a761bd8de445840ef68e4d1a)"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
!8 = distinct !{!8, !7}
