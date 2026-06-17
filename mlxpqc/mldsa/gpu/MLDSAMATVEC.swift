// MLDSAMATVEC — ML-DSA-65 matvec t = A·s1hat (+reduce, invntt_tomont) + s2,
// then caddq + power2round -> (t1, t0). One threadgroup per (key,row).
// Validated bit-exact vs pq-crystals reference (polyvecl_pointwise_acc + invntt + power2round).
// Build: swiftc -O MLDSAMATVEC.swift -o mldsa_matvec -framework Metal -framework Foundation

import Foundation
import Metal

let K = 6, L = 5                       // ML-DSA-65
let QI: Int32 = 8380417
let QL: Int64 = 8380417
let QINV: Int32 = 58728449
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
@inline(__always) func montReduce(_ a: Int64) -> Int32 {
    let t0 = Int32(truncatingIfNeeded: a) &* QINV
    return Int32(truncatingIfNeeded: (a &- Int64(t0) &* QL) >> 32)
}
func reduce32(_ a: Int32) -> Int32 { let t = (a &+ (1 << 22)) >> 23; return a &- t &* QI }
func caddq(_ a: Int32) -> Int32 { a &+ ((a >> 31) & QI) }
func invnttRef(_ a: inout [Int32]) {
    let f: Int64 = 41978; var k = 256, len = 1
    while len < 256 {
        var start = 0
        while start < 256 {
            k -= 1; let zeta = -Int64(ZETAS[k]); var j = start
            while j < start + len {
                let t = a[j]; a[j] = t &+ a[j+len]; a[j+len] = t &- a[j+len]
                a[j+len] = montReduce(zeta &* Int64(a[j+len])); j += 1
            }
            start = j + len
        }
        len <<= 1
    }
    for j in 0..<256 { a[j] = montReduce(f &* Int64(a[j])) }
}

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
inline int mont_reduce(long a) { int t = (int)a * DQINV; long r = (a - (long)t*(long)DQ) >> 32; return (int)r; }
inline int reduce32(int a) { int t = (a + (1<<22)) >> 23; return a - t*DQ; }
inline int caddq(int a) { return a + ((a>>31) & DQ); }
kernel void matvec(device const int* A [[buffer(0)]],
                   device const int* s1hat [[buffer(1)]],
                   device const int* s2 [[buffer(2)]],
                   device int* t1out [[buffer(3)]],
                   device int* t0out [[buffer(4)]],
                   constant uint& KK [[buffer(5)]],
                   constant uint& LL [[buffer(6)]],
                   uint tid [[thread_position_in_threadgroup]],
                   uint tg  [[threadgroup_position_in_grid]],
                   threadgroup int* a [[threadgroup(0)]]) {
    uint key = tg / KK, row = tg % KK;
    uint c0 = tid, c1 = tid + 128u;
    int acc0 = 0, acc1 = 0;
    for (uint j = 0; j < LL; ++j) {
        uint aB = ((key*KK + row)*LL + j) * 256u;
        uint sB = (key*LL + j) * 256u;
        acc0 += mont_reduce((long)A[aB+c0] * (long)s1hat[sB+c0]);
        acc1 += mont_reduce((long)A[aB+c1] * (long)s1hat[sB+c1]);
    }
    a[c0] = reduce32(acc0); a[c1] = reduce32(acc1);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    // invntt_tomont
    for (uint len = 1u; len < 256u; len <<= 1u) {
        uint g = tid / len;
        int zeta = -ZETAS[(256u/len) - 1u - g];
        uint j = g*(2u*len) + (tid % len); uint jp = j + len;
        int t = a[j], u = a[jp];
        a[j] = t + u; a[jp] = mont_reduce((long)zeta * (long)(t - u));
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    const int f = 41978;
    a[c0] = mont_reduce((long)f * (long)a[c0]); a[c1] = mont_reduce((long)f * (long)a[c1]);
    // add s2, caddq, power2round (D=13)
    uint s2B = (key*KK + row) * 256u, ob = tg * 256u;
    int v0 = caddq(a[c0] + s2[s2B+c0]); int u1 = (v0 + 4095) >> 13;
    t1out[ob+c0] = u1; t0out[ob+c0] = v0 - (u1 << 13);
    int v1 = caddq(a[c1] + s2[s2B+c1]); int w1 = (v1 + 4095) >> 13;
    t1out[ob+c1] = w1; t0out[ob+c1] = v1 - (w1 << 13);
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "matvec")!)

print("=== MLDSAMATVEC — ML-DSA-65 matvec+power2round on Metal vs reference ===\n")
let N = 1024
var rng: UInt64 = 0xABCDEF0123456789
func r32() -> Int32 { rng ^= rng<<13; rng ^= rng>>7; rng ^= rng<<17; return Int32(truncatingIfNeeded: rng) }
func uniq() -> Int32 { var v = r32() % QI; if v < 0 { v += QI }; return v }

var A = [Int32](repeating: 0, count: N*K*L*256)
var s1h = [Int32](repeating: 0, count: N*L*256)
var s2 = [Int32](repeating: 0, count: N*K*256)
for i in 0..<A.count { A[i] = uniq() }
for i in 0..<s1h.count { s1h[i] = uniq() }
for i in 0..<s2.count { s2[i] = (r32() & 7) - 4 }   // [-4,3], eta-ish range

// reference
var t1r = [Int32](repeating: 0, count: N*K*256), t0r = t1r
for key in 0..<N { for row in 0..<K {
    var acc = [Int32](repeating: 0, count: 256)
    for j in 0..<L { let aOff = ((key*K+row)*L+j)*256, sOff = (key*L+j)*256
        for c in 0..<256 { acc[c] = acc[c] &+ montReduce(Int64(A[aOff+c]) &* Int64(s1h[sOff+c])) } }
    for c in 0..<256 { acc[c] = reduce32(acc[c]) }
    invnttRef(&acc)
    let s2Off = (key*K+row)*256, ob = (key*K+row)*256
    for c in 0..<256 { let v = caddq(acc[c] &+ s2[s2Off+c]); let u = (v &+ 4095) >> 13; t1r[ob+c] = u; t0r[ob+c] = v &- (u << 13) }
} }

// gpu
let aB = dev.makeBuffer(bytes: &A, length: A.count*4, options: .storageModeShared)!
let sB = dev.makeBuffer(bytes: &s1h, length: s1h.count*4, options: .storageModeShared)!
let s2B = dev.makeBuffer(bytes: &s2, length: s2.count*4, options: .storageModeShared)!
let t1B = dev.makeBuffer(length: N*K*256*4, options: .storageModeShared)!
let t0B = dev.makeBuffer(length: N*K*256*4, options: .storageModeShared)!
var kk = UInt32(K), ll = UInt32(L)
let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
e.setComputePipelineState(pso)
e.setBuffer(aB,offset:0,index:0); e.setBuffer(sB,offset:0,index:1); e.setBuffer(s2B,offset:0,index:2)
e.setBuffer(t1B,offset:0,index:3); e.setBuffer(t0B,offset:0,index:4); e.setBytes(&kk,length:4,index:5); e.setBytes(&ll,length:4,index:6)
e.setThreadgroupMemoryLength(256*4, index:0)
e.dispatchThreadgroups(MTLSize(width: N*K, height:1, depth:1), threadsPerThreadgroup: MTLSize(width:128,height:1,depth:1))
e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
let t1g = Array(UnsafeBufferPointer(start: t1B.contents().bindMemory(to: Int32.self, capacity: N*K*256), count: N*K*256))
let t0g = Array(UnsafeBufferPointer(start: t0B.contents().bindMemory(to: Int32.self, capacity: N*K*256), count: N*K*256))
print("matvec + power2round (\(N) keys, K=\(K) L=\(L)) : \((t1g == t1r && t0g == t0r) ? "PASS" : "FAIL")")
