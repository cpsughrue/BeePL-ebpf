Over the past two weeks, I had some time to explore LLVM analysis passes, LLVM transformation passes, and [type unboxing](https://discourse.llvm.org/t/newtype-optimisations-and-field-unpacking/78755). I first familiarized myself with LLVM IR and how to write a pass. I created a [simple-llvm-template](https://github.com/cpsughrue/simple-llvm-template), based on a [talk](https://youtu.be/ar7cJl2aBuU?si=xVZm9uWA_pyU1w0l) I found, which contains an analysis pass, a transformation pass, and LLVM LIT tests. I then spent time investigating how the LLVM optimizer, as is, transforms Koka's boxed types and where we would benefit from writting additional passes.

### LLVM IR Discoveries

The LLVM optimizer already does some unboxing. For example, when `foo` is compiled to LLVM IR with `-O0` and `-O1` the argument and return value are transformed from `box_t` to `i8`.

```c
#include <stdint.h>

typedef struct {
  int8_t data;
} box_t;

box_t foo(box_t bar) {
  return bar;
}
```
`clang -emit-llvm -S -O0 struct.c -o struct.ll`

<pre><code>
%struct.box_t = type { i8 }

; Function Attrs: noinline nounwind optnone uwtable
<strong>define dso_local i8 @foo(i8 %0) #0 {</strong>
  %2 = alloca %struct.box_t, align 1
  %3 = alloca %struct.box_t, align 1
  %4 = getelementptr inbounds %struct.box_t, %struct.box_t* %3, i32 0, i32 0
  store i8 %0, i8* %4, align 1
  %5 = bitcast %struct.box_t* %2 to i8*
  %6 = bitcast %struct.box_t* %3 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %5, i8* align 1 %6, i64 1, i1 false)
  %7 = getelementptr inbounds %struct.box_t, %struct.box_t* %2, i32 0, i32 0
  %8 = load i8, i8* %7, align 1
  <strong>ret i8 %8</strong>
}
</code></pre>

`clang -emit-llvm -S -O1 struct.c -o struct.ll`

<pre><code>
; Function Attrs: norecurse nounwind readnone uwtable
<strong>define dso_local i8 @foo(i8 returned %0) local_unnamed_addr #0 {</strong>
  <strong>ret i8 %0</strong>
}
</pre></code>
<br>


When I use `foo` within a `main` function we see that the argument and return value are still treated as an `i8`.

```c
#include <stdint.h>

typedef struct {
  int8_t data;
} box_t;

box_t foo(box_t bar) {
  return bar;
}

int main() {
  box_t Box1 = {.data = 1};
  box_t Box2 = foo(Box1);
  return 0;
}
```
`clang -emit-llvm -S -O0 struct.c -o struct.ll`

<pre><code>
%struct.box_t = type { i8 }

@__const.main.OldValue = private unnamed_addr constant %struct.box_t { i8 1 }, align 1

; Function Attrs: noinline nounwind optnone uwtable
<strong>define dso_local i8 @foo(i8 %0) #0 {</strong>
  %2 = alloca %struct.box_t, align 1
  %3 = alloca %struct.box_t, align 1
  %4 = getelementptr inbounds %struct.box_t, %struct.box_t* %3, i32 0, i32 0
  store i8 %0, i8* %4, align 1
  %5 = bitcast %struct.box_t* %2 to i8*
  %6 = bitcast %struct.box_t* %3 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %5, i8* align 1 %6, i64 1, i1 false)
  %7 = getelementptr inbounds %struct.box_t, %struct.box_t* %2, i32 0, i32 0
  %8 = load i8, i8* %7, align 1
  <strong>ret i8 %8</strong>
}

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca %struct.box_t, align 1
  %3 = alloca %struct.box_t, align 1
  store i32 0, i32* %1, align 4
  <strong>%4 = bitcast %struct.box_t* %2 to i8*</strong>
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %4, i8* align 1 getelementptr inbounds (%struct.box_t, %struct.box_t* @__const.main.OldValue, i32 0, i32 0), i64 1, i1 false)
  %5 = getelementptr inbounds %struct.box_t, %struct.box_t* %2, i32 0, i32 0
  %6 = load i8, i8* %5, align 1
  <strong>%7 = call i8 @foo(i8 %6)</strong>
  %8 = getelementptr inbounds %struct.box_t, %struct.box_t* %3, i32 0, i32 0
  store i8 %7, i8* %8, align 1
  %9 = getelementptr inbounds %struct.box_t, %struct.box_t* %3, i32 0, i32 0
  %10 = load i8, i8* %9, align 1
  %11 = sext i8 %10 to i32
  ret i32 %11
}
</code></pre>
<br>


When I create a `struct box_t` with two elements of size `i8` they still get unboxed, but instead of passing them into `foo` as two seperate `i8` arguments they get passed in as a single `i16`.
```c
#include <stdint.h>

typedef struct {
  int8_t data1;
  int8_t data2;
} box_t;

box_t foo(box_t bar) {
  return bar;
}
```

`clang -emit-llvm -S -O0 struct.c -o struct.ll`
<pre><code>
%struct.box_t = type { i8, i8 }

; Function Attrs: noinline nounwind optnone uwtable
<strong>define dso_local i16 @foo(i16 %0) #0 {</strong>
  %2 = alloca %struct.box_t, align 1
  %3 = alloca %struct.box_t, align 1
  %4 = bitcast %struct.box_t* %3 to i16*
  store i16 %0, i16* %4, align 1
  %5 = bitcast %struct.box_t* %2 to i8*
  %6 = bitcast %struct.box_t* %3 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 1 %5, i8* align 1 %6, i64 2, i1 false)
  %7 = bitcast %struct.box_t* %2 to i16*
  %8 = load i16, i16* %7, align 1
  <strong>ret i16 %8</strong>
}
</code></pre>

`clang -emit-llvm -S -O1 struct.c -o struct.ll`
<pre><code>
; Function Attrs: norecurse nounwind readnone uwtable
<strong>define dso_local i16 @foo(i16 returned %0) local_unnamed_addr #0 {</strong>
  <strong>ret i16 %0</strong>
}
</code></pre>
<br>

As long as `sizeof(box_t)` is 128 bytes or less the LLVM optimizer will unbox `box_t` and pass its contents to `foo` as integer arguments. Once `sizeof(box_t)` is larger then 64 bytes `foo` begins to return a structured value.

```c
#include <stdint.h>

typedef struct {
  int8_t data[16];
} box_t;

box_t foo(box_t bar) {
  return bar;
}
```

`clang -emit-llvm -S -O1 struct.c -o struct.ll`
<pre><code>
; Function Attrs: norecurse nounwind readnone uwtable
<strong>define dso_local { i64, i64 } @foo(i64 %0, i64 %1) local_unnamed_addr #0 {</strong>
  %3 = insertvalue { i64, i64 } undef, i64 %0, 0
  %4 = insertvalue { i64, i64 } %3, i64 %1, 1
  <strong>ret { i64, i64 } %4</strong>
}
</code></pre>
<br>

As soon as `sizeof(box_t)` exceeds 128 bytes the LLVM optimizer passes the struct to `foo` by value instead of unboxing its contents.
```c
#include <stdint.h>

typedef struct {
  int8_t data[17];
} box_t;

box_t foo(box_t bar) {
  return bar;
}
```

`clang -emit-llvm -S -O1 struct.c -o struct.ll`
<pre><code>
%struct.box_t = type { [17 x i8] }

; Function Attrs: nounwind uwtable
<strong>define dso_local void @foo(%struct.box_t* noalias nocapture sret %0, %struct.box_t* nocapture readonly byval(%struct.box_t) align 8 %1) local_unnamed_addr #0 {</strong>
  %3 = getelementptr inbounds %struct.box_t, %struct.box_t* %0, i64 0, i32 0, i64 0
  %4 = getelementptr inbounds %struct.box_t, %struct.box_t* %1, i64 0, i32 0, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 dereferenceable(17) %3, i8* nonnull align 8 dereferenceable(17) %4, i64 17, i1 false), !tbaa.struct !2
  ret void
}
</code></pre>
<br>

We see the same behavior in a koka specific example
```c
#include <stdint.h>

// kklib/Platform.h
typedef intptr_t kk_intb_t;

// kklib.h
typedef struct kk_integer_s {
  kk_intb_t ibox;
} kk_integer_t;

kk_integer_t foo(kk_integer_t bar) {
  return bar;
}
```

`clang -emit-llvm -S -O0 struct.c -o struct.ll`
<pre><code>
%struct.kk_integer_s = type { i64 }

; Function Attrs: noinline nounwind optnone uwtable
<strong>define dso_local i64 @foo(i64 %0) #0 {</strong>
  %2 = alloca %struct.kk_integer_s, align 8
  %3 = alloca %struct.kk_integer_s, align 8
  %4 = getelementptr inbounds %struct.kk_integer_s, %struct.kk_integer_s* %3, i32 0, i32 0
  store i64 %0, i64* %4, align 8
  %5 = bitcast %struct.kk_integer_s* %2 to i8*
  %6 = bitcast %struct.kk_integer_s* %3 to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 8 %5, i8* align 8 %6, i64 8, i1 false)
  %7 = getelementptr inbounds %struct.kk_integer_s, %struct.kk_integer_s* %2, i32 0, i32 0
  %8 = load i64, i64* %7, align 8
  <strong>ret i64 %8</strong>
}
</code></pre>

`clang -emit-llvm -S -O1 struct.c -o struct.ll`
<pre><code>
; Function Attrs: norecurse nounwind readnone uwtable
<strong>define dso_local i64 @foo(i64 returned %0) local_unnamed_addr #0 {</strong>
  <strong>ret i64 %0</strong>
}
</code></pre>

### eBPF

After looking into how the LLVM optimizer handles different basic structs I tried to construct a `c` program that could potentially be generated by the koka compiler but that the eBPF verifier would reject due to its use of a struct. My goal was to create a concrete example I could use to help test that a struct handling LLVM pass worked. I used a simple packet counter program as a base.  
```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")
int packet_count(void *ctx) {
    bpf_printk("%d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```
This is where I left off. I got eBPF set up and can load/unload xdp programs. I am still working on creating an xdp program that gets rejected by the eBPF verifier due to its use of a struct. It has been harder then I expected, potentially because LLVM already unboxes simple structs, but I think I am pretty close to getting there.

### Other questions I need to figure out
* I need to figure out if it is problematic for a function to return a struct in an eBPF program (e.g., `ret { i64, i64 } %4`)
* The LLVM IR for `foo` sometimes still makes references to the struct in its body (e.g., `%2 = alloca %struct.kk_integer_s, align 8`). I need to figure out if that's problematic for eBPF programs

### Potential Next Steps
1. Continue working on creating an eBPF program "broken" by its use of structs then write an LLVM pass to "fix" it or determine for certain that the LLVM optimizer already does enogh to unbox structs
2. Write a pass so that `box_t` gets passed to `foo` as two `i8` instead of one `i16`
```c
typedef struct {
  int8_t data1;
  int8_t data2;
} box_t;

box_t foo(box_t bar) {
  return bar;
}
```
```
@foo(i8 %0, i8 %1)
```
3. Write a pass so that a large struct (`sizeof(box_t) > 128`) gets passed to `foo` as a pointer to its first element instead of as a struct
```c
#include <stdint.h>

typedef struct {
  int8_t data1[17];
} box_t;

int8_t foo(box_t bar) {
  return 0;
}
```
```
i8 @foo(i8* %0)
```
4. Whatever else you want me to do
