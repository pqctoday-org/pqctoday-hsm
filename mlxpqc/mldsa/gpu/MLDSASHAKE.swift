// MLDSASHAKE — SHAKE128/256 on Metal (sponge around validated Keccak-f[1600]),
// one thread per instance. Validated against the known empty-input vectors AND a
// faithful port of ref/fips202.c for the ExpandA/ExpandS input shapes.
// Build: swiftc -O MLDSASHAKE.swift -o mldsa_shake -framework Metal -framework Foundation

import Foundation
import Metal

// ---- CPU reference (port of ref/fips202.c) ----
let RHO = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
let PIL = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]
let RC: [UInt64] = [
 0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,
 0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,
 0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
 0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
 0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,
 0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
func rotl(_ x: UInt64, _ n: Int) -> UInt64 { n == 0 ? x : (x << n) | (x >> (64 - n)) }
func keccakf(_ a: inout [UInt64]) {
    for r in 0..<24 {
        var b = [UInt64](repeating: 0, count: 5)
        for i in 0..<5 { b[i] = a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20] }
        for i in 0..<5 { let t = b[(i+4)%5] ^ rotl(b[(i+1)%5],1); var j = 0; while j < 25 { a[j+i] ^= t; j += 5 } }
        var t = a[1]
        for i in 0..<24 { let j = PIL[i]; let tmp = a[j]; a[j] = rotl(t, RHO[i]); t = tmp }
        var j = 0
        while j < 25 { var c = [UInt64](repeating: 0, count: 5); for i in 0..<5 { c[i] = a[j+i] }; for i in 0..<5 { a[j+i] = c[i] ^ ((~c[(i+1)%5]) & c[(i+2)%5]) }; j += 5 }
        a[0] ^= RC[r]
    }
}
func shakeRef(_ input: [UInt8], rate: Int, outBlocks: Int, domain: UInt8 = 0x1F) -> [UInt8] {
    var s = [UInt64](repeating: 0, count: 25)
    var inlen = input.count, off = 0
    while inlen >= rate { for i in 0..<(rate/8) { var v: UInt64 = 0; for b in 0..<8 { v |= UInt64(input[off+8*i+b]) << (8*b) }; s[i] ^= v }; off += rate; inlen -= rate; keccakf(&s) }
    for i in 0..<inlen { s[i/8] ^= UInt64(input[off+i]) << (8*(i%8)) }
    s[inlen/8] ^= UInt64(domain) << (8*(inlen%8))
    s[(rate-1)/8] ^= UInt64(1) << 63
    var out = [UInt8]()
    for _ in 0..<outBlocks { keccakf(&s); for i in 0..<(rate/8) { let v = s[i]; for b in 0..<8 { out.append(UInt8((v >> (8*b)) & 0xff)) } } }
    return out
}
func hex(_ b: ArraySlice<UInt8>) -> String { b.map { String(format: "%02x", $0) }.joined() }

// ---- Metal SHAKE ----
let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant ulong RC[24] = {
 0x0000000000000001ul,0x0000000000008082ul,0x800000000000808aul,0x8000000080008000ul,
 0x000000000000808bul,0x0000000080000001ul,0x8000000080008081ul,0x8000000000008009ul,
 0x000000000000008aul,0x0000000000000088ul,0x0000000080008009ul,0x000000008000000aul,
 0x000000008000808bul,0x800000000000008bul,0x8000000000008089ul,0x8000000000008003ul,
 0x8000000000008002ul,0x8000000000000080ul,0x000000000000800aul,0x800000008000000aul,
 0x8000000080008081ul,0x8000000000008080ul,0x0000000080000001ul,0x8000000080008008ul };
constant uint RHO[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant uint PIL[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rotl64(ulong x, uint n) { return (x << n) | (x >> (64 - n)); }
inline void keccakf(thread ulong* a) {
    for (int r = 0; r < 24; ++r) {
        ulong b[5];
        for (int i = 0; i < 5; ++i) b[i] = a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];
        for (int i = 0; i < 5; ++i) { ulong t = b[(i+4)%5] ^ rotl64(b[(i+1)%5],1); for (int j=0;j<25;j+=5) a[j+i] ^= t; }
        ulong t = a[1];
        for (int i = 0; i < 24; ++i) { uint j = PIL[i]; ulong tmp = a[j]; a[j] = rotl64(t, RHO[i]); t = tmp; }
        for (int j = 0; j < 25; j += 5) { ulong c[5]; for (int i=0;i<5;i++) c[i]=a[j+i]; for (int i=0;i<5;i++) a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5]); }
        a[0] ^= RC[r];
    }
}
kernel void shake(device const uchar* inp [[buffer(0)]],
                  device uchar* outp [[buffer(1)]],
                  constant uint& rate [[buffer(2)]],
                  constant uint& inlen [[buffer(3)]],
                  constant uint& inStride [[buffer(4)]],
                  constant uint& outBlocks [[buffer(5)]],
                  constant uint& outStride [[buffer(6)]],
                  constant uint& domain [[buffer(7)]],
                  uint gid [[thread_position_in_grid]]) {
    ulong s[25]; for (uint i = 0; i < 25u; ++i) s[i] = 0ul;
    uint ibase = gid * inStride, off = 0u, rem = inlen;
    while (rem >= rate) {
        for (uint i = 0; i < rate/8u; ++i) { ulong v = 0; for (uint b=0;b<8u;b++) v |= (ulong)inp[ibase+off+8u*i+b] << (8u*b); s[i] ^= v; }
        off += rate; rem -= rate; keccakf(s);
    }
    for (uint i = 0; i < rem; ++i) s[i/8u] ^= (ulong)inp[ibase+off+i] << (8u*(i%8u));
    s[rem/8u] ^= (ulong)domain << (8u*(rem%8u));
    s[(rate-1u)/8u] ^= (ulong)1 << 63;
    uint obase = gid * outStride;
    for (uint blk = 0; blk < outBlocks; ++blk) {
        keccakf(s);
        for (uint i = 0; i < rate/8u; ++i) { ulong v = s[i]; for (uint b=0;b<8u;b++) outp[obase+blk*rate+8u*i+b] = (uchar)(v >> (8u*b)); }
    }
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
let pso = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "shake")!)

func gpuShake(_ inputs: [[UInt8]], rate: Int, outBlocks: Int, domain: UInt8 = 0x1F) -> [[UInt8]] {
    let n = inputs.count, inStride = inputs.map { $0.count }.max() ?? 0, inlen = inputs[0].count
    let outStride = outBlocks * rate
    var inFlat = [UInt8](repeating: 0, count: n * inStride)
    for i in 0..<n { for j in 0..<inputs[i].count { inFlat[i*inStride+j] = inputs[i][j] } }
    let inB = dev.makeBuffer(bytes: &inFlat, length: max(1, n*inStride), options: .storageModeShared)!
    let outB = dev.makeBuffer(length: n*outStride, options: .storageModeShared)!
    var r = UInt32(rate), il = UInt32(inlen), iss = UInt32(inStride), ob = UInt32(outBlocks), os = UInt32(outStride), dm = UInt32(domain)
    let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(pso); e.setBuffer(inB, offset: 0, index: 0); e.setBuffer(outB, offset: 0, index: 1)
    e.setBytes(&r, length: 4, index: 2); e.setBytes(&il, length: 4, index: 3); e.setBytes(&iss, length: 4, index: 4)
    e.setBytes(&ob, length: 4, index: 5); e.setBytes(&os, length: 4, index: 6); e.setBytes(&dm, length: 4, index: 7)
    e.dispatchThreads(MTLSize(width: n, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 256, height: 1, depth: 1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    let p = outB.contents().bindMemory(to: UInt8.self, capacity: n*outStride)
    return (0..<n).map { Array(UnsafeBufferPointer(start: p + $0*outStride, count: outStride)) }
}

print("=== MLDSASHAKE — SHAKE128/256 on Metal vs reference ===\n")

// 1) known-answer vectors (empty input)
let v128 = gpuShake([[]], rate: 168, outBlocks: 1)[0]
let v256 = gpuShake([[]], rate: 136, outBlocks: 1)[0]
let kat128 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
let kat256 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
print("SHAKE128(\"\") KAT : \(hex(v128[0..<32]) == kat128 ? "PASS" : "FAIL \(hex(v128[0..<32]))")")
print("SHAKE256(\"\") KAT : \(hex(v256[0..<32]) == kat256 ? "PASS" : "FAIL \(hex(v256[0..<32]))")")

// 2) GPU == reference for ExpandA (SHAKE128, 34B in, 5 blk) and ExpandS (SHAKE256, 66B in, 5 blk)
var rng: UInt64 = 0xCAFEBABEF00DD00D
func rb(_ n: Int) -> [UInt8] { (0..<n).map { _ in rng ^= rng<<13; rng ^= rng>>7; rng ^= rng<<17; return UInt8(truncatingIfNeeded: rng) } }
for (name, rate, inlen, blocks) in [("ExpandA SHAKE128", 168, 34, 5), ("ExpandS SHAKE256", 136, 66, 5)] {
    let batch = 4096
    let ins = (0..<batch).map { _ in rb(inlen) }
    let g = gpuShake(ins, rate: rate, outBlocks: blocks)
    var okAll = true
    for i in 0..<batch where g[i] != shakeRef(ins[i], rate: rate, outBlocks: blocks) { okAll = false; break }
    print("\(name), \(batch) instances : \(okAll ? "PASS" : "FAIL")")
}

// 3) throughput: ExpandS-shape SHAKE256, CPU-allcore vs GPU
print("\nThroughput (M SHAKE/sec), SHAKE256 66B->5blk:")
for batch in [4096, 65536, 262144] {
    let ins = (0..<batch).map { _ in rb(66) }
    // warm
    _ = gpuShake(ins, rate: 136, outBlocks: 5)
    var tg = [Double]()
    for _ in 0..<5 {
        let inStride = 66, outStride = 5*136
        var inFlat = [UInt8](repeating: 0, count: batch*inStride); for i in 0..<batch { for j in 0..<66 { inFlat[i*inStride+j] = ins[i][j] } }
        let inB = dev.makeBuffer(bytes: &inFlat, length: batch*inStride, options: .storageModeShared)!
        let outB = dev.makeBuffer(length: batch*outStride, options: .storageModeShared)!
        var r = UInt32(136), il = UInt32(66), iss = UInt32(inStride), ob = UInt32(5), os = UInt32(outStride), dm = UInt32(0x1F)
        let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
        e.setComputePipelineState(pso); e.setBuffer(inB,offset:0,index:0); e.setBuffer(outB,offset:0,index:1)
        e.setBytes(&r,length:4,index:2); e.setBytes(&il,length:4,index:3); e.setBytes(&iss,length:4,index:4); e.setBytes(&ob,length:4,index:5); e.setBytes(&os,length:4,index:6); e.setBytes(&dm,length:4,index:7)
        e.dispatchThreads(MTLSize(width: batch, height:1, depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1))
        e.endEncoding(); cb.commit(); cb.waitUntilCompleted(); tg.append(cb.gpuEndTime - cb.gpuStartTime)
    }
    tg.sort(); let gpu = Double(batch) / tg[tg.count/2] / 1e6
    var tc = [Double]()
    for _ in 0..<2 { let s = Date(); DispatchQueue.concurrentPerform(iterations: batch) { i in _ = shakeRef(ins[i], rate: 136, outBlocks: 5) }; tc.append(-s.timeIntervalSinceNow) }
    tc.sort(); let cpu = Double(batch) / tc[tc.count/2] / 1e6
    print(" batch \(batch): CPU-allcore \(String(format:"%.2f",cpu))  GPU \(String(format:"%.2f",gpu))  (\(String(format:"%.1f",gpu/cpu))x)")
}
