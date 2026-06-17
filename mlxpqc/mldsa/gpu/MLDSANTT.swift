// MLDSANTT — real Dilithium (ML-DSA / FIPS-204) forward NTT on Metal,
// validated BIT-EXACT against a faithful CPU port of the pq-crystals reference
// (../ref/ntt.c, ../ref/reduce.c). Also times CPU-1-core vs CPU-all-cores vs GPU
// across batch sizes to find the CPU->GPU crossover.
//
// Base: pq-crystals/dilithium reference (Public Domain / Apache-2.0). corecrypto
// is used only as a read-only oracle elsewhere; NOT forked (license forbids it).
//
// Build: swiftc -O MLDSANTT.swift -o mldsa_ntt -framework Metal -framework Foundation
// Run:   ./mldsa_ntt

import Foundation
import Metal

// ---- Dilithium constants (../ref/params.h, ../ref/reduce.h)
let QI: Int32 = 8380417           // Q
let QL: Int64 = 8380417
let QINV: Int32 = 58728449        // q^-1 mod 2^32
let ZETAS: [Int32] = [
0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
]

// ---- CPU reference (faithful port of ref/reduce.c + ref/ntt.c), pointer-based
@inline(__always) func montReduce(_ a: Int64) -> Int32 {
    let t0 = Int32(truncatingIfNeeded: a) &* QINV          // (int32_t)a * QINV, 32-bit wrap
    return Int32(truncatingIfNeeded: (a &- Int64(t0) &* QL) >> 32)
}
func nttRef(_ a: UnsafeMutablePointer<Int32>) {
    var k = 0, len = 128
    while len > 0 {
        var start = 0
        while start < 256 {
            k += 1
            let zeta = Int64(ZETAS[k])
            var j = start
            while j < start + len {
                let t = montReduce(zeta &* Int64(a[j + len]))
                a[j + len] = a[j] &- t
                a[j] = a[j] &+ t
                j += 1
            }
            start = j + len
        }
        len >>= 1
    }
}

func invnttRef(_ a: UnsafeMutablePointer<Int32>) {
    let f: Int64 = 41978
    var k = 256, len = 1
    while len < 256 {
        var start = 0
        while start < 256 {
            k -= 1
            let zeta = -Int64(ZETAS[k])
            var j = start
            while j < start + len {
                let t = a[j]
                a[j] = t &+ a[j + len]
                a[j + len] = t &- a[j + len]
                a[j + len] = montReduce(zeta &* Int64(a[j + len]))
                j += 1
            }
            start = j + len
        }
        len <<= 1
    }
    for j in 0..<256 { a[j] = montReduce(f &* Int64(a[j])) }
}
func pointwiseRef(_ c: UnsafeMutablePointer<Int32>, _ a: UnsafePointer<Int32>, _ b: UnsafePointer<Int32>) {
    for i in 0..<256 { c[i] = montReduce(Int64(a[i]) &* Int64(b[i])) }
}
// freeze: standard representative in [0,Q) (ref/reduce.c reduce32 + caddq)
func reduce32(_ a: Int32) -> Int32 { let t = (a &+ (1 << 22)) >> 23; return a &- t &* QI }
func caddq(_ a: Int32) -> Int32 { a &+ ((a >> 31) & QI) }
func freeze(_ a: Int32) -> Int32 { caddq(reduce32(a)) }
// schoolbook negacyclic product in Z_q[X]/(X^256+1), coeffs in [0,Q) — ground truth
func schoolbook(_ a: [Int32], _ b: [Int32]) -> [Int32] {
    var c = [Int64](repeating: 0, count: 256)
    for i in 0..<256 { let ai = Int64(a[i]); for j in 0..<256 {
        let p = ai * Int64(b[j]); let k = i + j
        if k < 256 { c[k] += p } else { c[k - 256] -= p }
    } }
    return c.map { var r = $0 % QL; if r < 0 { r += QL }; return Int32(r) }
}

// ---- Metal: same NTT, one polynomial per threadgroup, 128 threads (1 butterfly/thread/level)
let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant int DQ = 8380417;
constant int DQINV = 58728449;
constant int ZETAS[256] = {
0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
-2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
-3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
-1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
-1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
-671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
-3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
-3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
-655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
-1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
-1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
-542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
-2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
-3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
-3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
-426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
-2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
-554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
};
inline int mont_reduce(long a) {
    int t = (int)a * DQINV;                 // (int32_t)a * QINV, 32-bit wrap
    long r = (a - (long)t * (long)DQ) >> 32;
    return (int)r;
}
kernel void ntt_dilithium(device const int* inp [[buffer(0)]],
                          device int* outp [[buffer(1)]],
                          uint tid [[thread_position_in_threadgroup]],
                          uint tg  [[threadgroup_position_in_grid]],
                          threadgroup int* a [[threadgroup(0)]]) {
    uint pbase = tg * 256u;
    a[tid] = inp[pbase + tid];
    a[tid + 128u] = inp[pbase + tid + 128u];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint len = 128u; len > 0u; len >>= 1u) {
        uint g = tid / len;
        int zeta = ZETAS[(128u / len) + g];
        uint j = g * (2u * len) + (tid % len);
        uint jp = j + len;
        int t = mont_reduce((long)zeta * (long)a[jp]);
        int aj = a[j];
        a[jp] = aj - t;
        a[j]  = aj + t;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    outp[pbase + tid] = a[tid];
    outp[pbase + tid + 128u] = a[tid + 128u];
}
// inverse NTT + mul by 2^32 (invntt_tomont), one poly per threadgroup
kernel void invntt_dilithium(device const int* inp [[buffer(0)]],
                             device int* outp [[buffer(1)]],
                             uint tid [[thread_position_in_threadgroup]],
                             uint tg  [[threadgroup_position_in_grid]],
                             threadgroup int* a [[threadgroup(0)]]) {
    uint pbase = tg * 256u;
    a[tid] = inp[pbase + tid];
    a[tid + 128u] = inp[pbase + tid + 128u];
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint len = 1u; len < 256u; len <<= 1u) {
        uint g = tid / len;
        int zeta = -ZETAS[(256u / len) - 1u - g];
        uint j = g * (2u * len) + (tid % len);
        uint jp = j + len;
        int t = a[j], u = a[jp];
        a[j]  = t + u;
        a[jp] = mont_reduce((long)zeta * (long)(t - u));
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    const int f = 41978;                       // mont^2 / 256
    a[tid]      = mont_reduce((long)f * (long)a[tid]);
    a[tid + 128u] = mont_reduce((long)f * (long)a[tid + 128u]);
    outp[pbase + tid] = a[tid];
    outp[pbase + tid + 128u] = a[tid + 128u];
}
// pointwise multiply in NTT domain, * 2^-32 (poly_pointwise_montgomery), elementwise
kernel void pointwise_mont(device const int* aa [[buffer(0)]],
                           device const int* bb [[buffer(1)]],
                           device int* cc [[buffer(2)]],
                           uint gid [[thread_position_in_grid]]) {
    cc[gid] = mont_reduce((long)aa[gid] * (long)bb[gid]);
}
"""

// ---- helpers
func sysctl(_ k: String) -> String { let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/sysctl"); p.arguments = ["-n", k]; let pi = Pipe(); p.standardOutput = pi; try? p.run(); let d = pi.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit(); return (String(data: d, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
func gpuCores() -> String { let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler"); p.arguments = ["SPDisplaysDataType"]; let pi = Pipe(); p.standardOutput = pi; try? p.run(); let d = pi.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit(); for l in (String(data: d, encoding: .utf8) ?? "").split(separator: "\n") where l.contains("Total Number of Cores") { return l.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces) } ?? "?" }; return "?" }
func median(_ x: [Double]) -> Double { let s = x.sorted(); return s.isEmpty ? 0 : s[s.count/2] }
func fmt(_ x: Double, _ d: Int = 2) -> String { String(format: "%.\(d)f", x) }

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "ntt_dilithium")!)

func makeBatch(_ batch: Int) -> [Int32] {
    var s: UInt64 = 0x243F6A8885A308D3
    return (0..<(batch * 256)).map { _ in s ^= s << 13; s ^= s >> 7; s ^= s << 17; return Int32(truncatingIfNeeded: s) % QI }   // in (-Q, Q)
}

print("=== MLDSANTT — Dilithium forward NTT, Metal vs CPU ===")
print("Chip: \(sysctl("machdep.cpu.brand_string")) | GPU cores: \(gpuCores()) | CPU: \(sysctl("hw.ncpu")) (P:\(sysctl("hw.perflevel0.physicalcpu")) E:\(sysctl("hw.perflevel1.physicalcpu")))")
print("Metal: \(dev.name) | unified=\(dev.hasUnifiedMemory)\n")

// ---- correctness: Metal == reference, bit-exact ----
let vbatch = 4096
var vin = makeBatch(vbatch)
let inBuf = dev.makeBuffer(bytes: &vin, length: vbatch*256*4, options: .storageModeShared)!
let outBuf = dev.makeBuffer(length: vbatch*256*4, options: .storageModeShared)!
do {
    let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(inBuf, offset: 0, index: 0); e.setBuffer(outBuf, offset: 0, index: 1)
    e.setThreadgroupMemoryLength(256*4, index: 0)
    e.dispatchThreadgroups(MTLSize(width: vbatch, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 128, height: 1, depth: 1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
let gpuOut = Array(UnsafeBufferPointer(start: outBuf.contents().bindMemory(to: Int32.self, capacity: vbatch*256), count: vbatch*256))
var cpuOut = vin
cpuOut.withUnsafeMutableBufferPointer { p in for i in 0..<vbatch { nttRef(p.baseAddress! + i*256) } }
let ok = gpuOut == cpuOut
print("CORRECTNESS (Metal NTT == pq-crystals reference, \(vbatch) polys, bit-exact): \(ok ? "PASS" : "FAIL")\n")
if !ok { print("First mismatch hunt:"); for i in 0..<(vbatch*256) where gpuOut[i] != cpuOut[i] { print("  idx \(i): gpu=\(gpuOut[i]) cpu=\(cpuOut[i])"); break } }

// ---- INTT, pointwise, and full-multiply validation ----
let psoInv = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "invntt_dilithium")!)
let psoPw  = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "pointwise_mont")!)
func runPoly(_ p: MTLComputePipelineState, _ inb: MTLBuffer, _ outb: MTLBuffer, _ batch: Int) {
    let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); e.setBuffer(inb, offset: 0, index: 0); e.setBuffer(outb, offset: 0, index: 1)
    e.setThreadgroupMemoryLength(256*4, index: 0)
    e.dispatchThreadgroups(MTLSize(width: batch, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 128, height: 1, depth: 1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
}
func read(_ b: MTLBuffer, _ n: Int) -> [Int32] { Array(UnsafeBufferPointer(start: b.contents().bindMemory(to: Int32.self, capacity: n), count: n)) }

// INTT bit-exact
var iin = makeBatch(vbatch)
let iInB = dev.makeBuffer(bytes: &iin, length: vbatch*256*4, options: .storageModeShared)!
let iOutB = dev.makeBuffer(length: vbatch*256*4, options: .storageModeShared)!
runPoly(psoInv, iInB, iOutB, vbatch)
var iCpu = iin; iCpu.withUnsafeMutableBufferPointer { p in for i in 0..<vbatch { invnttRef(p.baseAddress! + i*256) } }
print("CORRECTNESS (Metal INTT == reference, \(vbatch) polys): \(read(iOutB, vbatch*256) == iCpu ? "PASS" : "FAIL")")

// pointwise bit-exact
var pa = makeBatch(vbatch), pbv = makeBatch(vbatch)
let paB = dev.makeBuffer(bytes: &pa, length: vbatch*256*4, options: .storageModeShared)!
let pbB = dev.makeBuffer(bytes: &pbv, length: vbatch*256*4, options: .storageModeShared)!
let pcB = dev.makeBuffer(length: vbatch*256*4, options: .storageModeShared)!
do { let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!; e.setComputePipelineState(psoPw); e.setBuffer(paB,offset:0,index:0); e.setBuffer(pbB,offset:0,index:1); e.setBuffer(pcB,offset:0,index:2); e.dispatchThreads(MTLSize(width: vbatch*256, height:1, depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }
var pCpu = [Int32](repeating: 0, count: vbatch*256)
pCpu.withUnsafeMutableBufferPointer { c in pa.withUnsafeBufferPointer { aa in pbv.withUnsafeBufferPointer { bb in
    for i in 0..<vbatch { pointwiseRef(c.baseAddress! + i*256, aa.baseAddress! + i*256, bb.baseAddress! + i*256) } } } }
print("CORRECTNESS (Metal pointwise == reference, \(vbatch) polys): \(read(pcB, vbatch*256) == pCpu ? "PASS" : "FAIL")")

// full pipeline: invntt(pointwise(ntt(a), ntt(b))) == schoolbook(a,b) mod q
let mb = 64
var ma = makeBatch(mb), mbv = makeBatch(mb)
for i in 0..<(mb*256) { if ma[i] < 0 { ma[i] += QI }; if mbv[i] < 0 { mbv[i] += QI } }   // [0,Q)
let maB = dev.makeBuffer(bytes: &ma, length: mb*256*4, options: .storageModeShared)!
let mbB = dev.makeBuffer(bytes: &mbv, length: mb*256*4, options: .storageModeShared)!
let naB = dev.makeBuffer(length: mb*256*4, options: .storageModeShared)!
let nbB = dev.makeBuffer(length: mb*256*4, options: .storageModeShared)!
let ncB = dev.makeBuffer(length: mb*256*4, options: .storageModeShared)!
let nrB = dev.makeBuffer(length: mb*256*4, options: .storageModeShared)!
runPoly(pso, maB, naB, mb); runPoly(pso, mbB, nbB, mb)
do { let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!; e.setComputePipelineState(psoPw); e.setBuffer(naB,offset:0,index:0); e.setBuffer(nbB,offset:0,index:1); e.setBuffer(ncB,offset:0,index:2); e.dispatchThreads(MTLSize(width: mb*256, height:1, depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }
runPoly(psoInv, ncB, nrB, mb)
let r = read(nrB, mb*256)
var mulOK = true
outer: for i in 0..<mb {
    let s = schoolbook(Array(ma[i*256..<(i+1)*256]), Array(mbv[i*256..<(i+1)*256]))
    for k in 0..<256 where freeze(r[i*256 + k]) != s[k] { mulOK = false; break outer }
}
print("CORRECTNESS (full NTT multiply == schoolbook a*b mod q, \(mb) polys): \(mulOK ? "PASS" : "FAIL")\n")

// ---- GPU warm-up (DVFS) ----
for _ in 0..<40 { let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!; e.setComputePipelineState(pso); e.setBuffer(inBuf, offset: 0, index: 0); e.setBuffer(outBuf, offset: 0, index: 1); e.setThreadgroupMemoryLength(256*4, index: 0); e.dispatchThreadgroups(MTLSize(width: vbatch, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 128, height: 1, depth: 1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }

// ---- throughput: CPU-1core, CPU-allcores, GPU, across batch sizes ----
print("Throughput (million NTTs/sec) — CPU vs GPU crossover:")
print(" batch     CPU-1core   CPU-allcore  GPU         GPU/CPU-all")
for batch in [256, 1024, 4096, 16384, 65536, 262144] {
    var data = makeBatch(batch)
    // CPU 1-core
    let c1 = data
    var t1: [Double] = []
    for _ in 0..<3 { var d = c1; let s = Date(); d.withUnsafeMutableBufferPointer { p in for i in 0..<batch { nttRef(p.baseAddress! + i*256) } }; t1.append(-s.timeIntervalSinceNow) }
    let cpu1 = Double(batch) / median(t1) / 1e6
    // CPU all-core
    var t2: [Double] = []
    for _ in 0..<3 { var d = c1; let s = Date(); d.withUnsafeMutableBufferPointer { p in let base = p.baseAddress!; DispatchQueue.concurrentPerform(iterations: batch) { i in nttRef(base + i*256) } }; t2.append(-s.timeIntervalSinceNow) }
    let cpuN = Double(batch) / median(t2) / 1e6
    // GPU
    let gi = dev.makeBuffer(bytes: &data, length: batch*256*4, options: .storageModeShared)!
    let go = dev.makeBuffer(length: batch*256*4, options: .storageModeShared)!
    var tg: [Double] = []
    for it in 0..<7 { let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!; e.setComputePipelineState(pso); e.setBuffer(gi, offset: 0, index: 0); e.setBuffer(go, offset: 0, index: 1); e.setThreadgroupMemoryLength(256*4, index: 0); e.dispatchThreadgroups(MTLSize(width: batch, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 128, height: 1, depth: 1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); if it >= 2 { tg.append(cb.gpuEndTime - cb.gpuStartTime) } }
    let gpu = Double(batch) / median(tg) / 1e6
    print(" \(String(batch).padding(toLength: 9, withPad: " ", startingAt: 0))\(fmt(cpu1).padding(toLength: 12, withPad: " ", startingAt: 0))\(fmt(cpuN).padding(toLength: 13, withPad: " ", startingAt: 0))\(fmt(gpu).padding(toLength: 12, withPad: " ", startingAt: 0))\(fmt(gpu/cpuN))x")
}
print("\nNote: GPU times are kernel-only (unified memory -> no host copy). CPU times are wall-clock.")
