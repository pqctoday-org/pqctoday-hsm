// MLDSASAMPLE — ExpandA (poly_uniform / rej_uniform) and ExpandS
// (poly_uniform_eta / rej_eta, ETA=4 = ML-DSA-65) on Metal, one poly per thread.
// SHAKE+rejection fused; validated bit-exact vs ref/poly.c.
// Build: swiftc -O MLDSASAMPLE.swift -o mldsa_sample -framework Metal -framework Foundation

import Foundation
import Metal

let Q: UInt32 = 8380417
// ---- keccak (CPU ref) ----
let RHO = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
let PIL = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]
let RC: [UInt64] = [0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
func rotl(_ x: UInt64, _ n: Int) -> UInt64 { n == 0 ? x : (x << n) | (x >> (64 - n)) }
func keccakf(_ a: inout [UInt64]) {
    for r in 0..<24 {
        var b = [UInt64](repeating: 0, count: 5)
        for i in 0..<5 { b[i] = a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20] }
        for i in 0..<5 { let t = b[(i+4)%5] ^ rotl(b[(i+1)%5],1); var j = 0; while j < 25 { a[j+i] ^= t; j += 5 } }
        var t = a[1]
        for i in 0..<24 { let j = PIL[i]; let tmp = a[j]; a[j] = rotl(t, RHO[i]); t = tmp }
        var j = 0; while j < 25 { var c = [UInt64](repeating: 0, count: 5); for i in 0..<5 { c[i] = a[j+i] }; for i in 0..<5 { a[j+i] = c[i] ^ ((~c[(i+1)%5]) & c[(i+2)%5]) }; j += 5 }
        a[0] ^= RC[r]
    }
}
func absorbInit(_ inp: [UInt8], rate: Int) -> [UInt64] {
    var s = [UInt64](repeating: 0, count: 25)
    for i in 0..<inp.count { s[i/8] ^= UInt64(inp[i]) << (8*(i%8)) }
    s[inp.count/8] ^= UInt64(0x1F) << (8*(inp.count%8))
    s[(rate-1)/8] ^= UInt64(1) << 63
    return s
}
func block(_ s: [UInt64], _ rate: Int) -> [UInt8] { var b = [UInt8](); for i in 0..<(rate/8) { let v = s[i]; for j in 0..<8 { b.append(UInt8((v >> (8*j)) & 0xff)) } }; return b }

func polyUniformRef(_ seed: [UInt8], _ nonce: UInt16) -> [Int32] {
    var s = absorbInit(seed + [UInt8(nonce & 0xff), UInt8(nonce >> 8)], rate: 168)
    var a = [Int32]()
    while a.count < 256 {
        keccakf(&s); let buf = block(s, 168); var pos = 0
        while pos + 3 <= 168 && a.count < 256 {
            let t = (UInt32(buf[pos]) | (UInt32(buf[pos+1]) << 8) | ((UInt32(buf[pos+2]) & 0x7f) << 16)); pos += 3
            if t < Q { a.append(Int32(t)) }
        }
    }
    return a
}
func polyUniformEtaRef(_ seed: [UInt8], _ nonce: UInt16) -> [Int32] {   // ETA=4
    var s = absorbInit(seed + [UInt8(nonce & 0xff), UInt8(nonce >> 8)], rate: 136)
    var a = [Int32]()
    while a.count < 256 {
        keccakf(&s); let buf = block(s, 136); var pos = 0
        while pos < 136 && a.count < 256 {
            let t0 = UInt32(buf[pos]) & 0x0F, t1 = UInt32(buf[pos]) >> 4; pos += 1
            if t0 < 9 { a.append(4 - Int32(t0)) }
            if t1 < 9 && a.count < 256 { a.append(4 - Int32(t1)) }
        }
    }
    return a
}

// ---- Metal ----
let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant uint Q = 8380417;
constant ulong RC[24] = {0x1ul,0x8082ul,0x800000000000808aul,0x8000000080008000ul,0x808bul,0x80000001ul,0x8000000080008081ul,0x8000000000008009ul,0x8aul,0x88ul,0x80008009ul,0x8000000aul,0x8000808bul,0x800000000000008bul,0x8000000000008089ul,0x8000000000008003ul,0x8000000000008002ul,0x8000000000000080ul,0x800aul,0x800000008000000aul,0x8000000080008081ul,0x8000000000008080ul,0x80000001ul,0x8000000080008008ul};
constant uint RHO[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant uint PIL[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rotl64(ulong x, uint n) { return (x<<n)|(x>>(64-n)); }
inline void keccakf(thread ulong* a) {
    for (int r=0;r<24;++r){ ulong b[5];
        for(int i=0;i<5;i++) b[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];
        for(int i=0;i<5;i++){ ulong t=b[(i+4)%5]^rotl64(b[(i+1)%5],1); for(int j=0;j<25;j+=5) a[j+i]^=t; }
        ulong t=a[1];
        for(int i=0;i<24;i++){ uint j=PIL[i]; ulong tmp=a[j]; a[j]=rotl64(t,RHO[i]); t=tmp; }
        for(int j=0;j<25;j+=5){ ulong c[5]; for(int i=0;i<5;i++)c[i]=a[j+i]; for(int i=0;i<5;i++)a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5]); }
        a[0]^=RC[r];
    }
}
inline void absorb(thread ulong* s, device const uchar* in, uint base, uint inlen, uint rate) {
    for (uint i=0;i<25u;i++) s[i]=0;
    for (uint i=0;i<inlen;i++) s[i/8u] ^= (ulong)in[base+i] << (8u*(i%8u));
    s[inlen/8u] ^= (ulong)0x1F << (8u*(inlen%8u));
    s[(rate-1u)/8u] ^= (ulong)1 << 63;
}
kernel void poly_uniform(device const uchar* seeds [[buffer(0)]], device int* out [[buffer(1)]],
                         constant uint& stride [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    ulong s[25]; absorb(s, seeds, gid*stride, 34u, 168u);
    uint ctr=0, obase=gid*256u; uchar buf[168];
    while (ctr < 256u) {
        keccakf(s);
        for (uint i=0;i<21u;i++){ ulong v=s[i]; for(uint b=0;b<8u;b++) buf[8u*i+b]=(uchar)(v>>(8u*b)); }
        for (uint pos=0; pos+3u<=168u && ctr<256u; pos+=3u) {
            uint t = (uint)buf[pos] | ((uint)buf[pos+1]<<8) | (((uint)buf[pos+2] & 0x7f)<<16);
            if (t < Q) out[obase + ctr++] = (int)t;
        }
    }
}
kernel void poly_uniform_eta(device const uchar* seeds [[buffer(0)]], device int* out [[buffer(1)]],
                             constant uint& stride [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
    ulong s[25]; absorb(s, seeds, gid*stride, 66u, 136u);
    uint ctr=0, obase=gid*256u; uchar buf[136];
    while (ctr < 256u) {
        keccakf(s);
        for (uint i=0;i<17u;i++){ ulong v=s[i]; for(uint b=0;b<8u;b++) buf[8u*i+b]=(uchar)(v>>(8u*b)); }
        for (uint pos=0; pos<136u && ctr<256u; pos+=1u) {
            uint t0 = (uint)buf[pos] & 0x0F, t1 = (uint)buf[pos] >> 4;
            if (t0 < 9u) out[obase + ctr++] = 4 - (int)t0;
            if (t1 < 9u && ctr < 256u) out[obase + ctr++] = 4 - (int)t1;
        }
    }
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
func pso(_ n: String) -> MTLComputePipelineState { try! dev.makeComputePipelineState(function: lib.makeFunction(name: n)!) }
let pUni = pso("poly_uniform"), pEta = pso("poly_uniform_eta")

func runSample(_ p: MTLComputePipelineState, _ seedsFlat: inout [UInt8], _ stride: Int, _ batch: Int) -> [Int32] {
    let inB = dev.makeBuffer(bytes: &seedsFlat, length: seedsFlat.count, options: .storageModeShared)!
    let outB = dev.makeBuffer(length: batch*256*4, options: .storageModeShared)!
    var st = UInt32(stride)
    let cb = queue.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
    e.setComputePipelineState(p); e.setBuffer(inB, offset:0, index:0); e.setBuffer(outB, offset:0, index:1); e.setBytes(&st, length:4, index:2)
    e.dispatchThreads(MTLSize(width: batch, height:1, depth:1), threadsPerThreadgroup: MTLSize(width:256,height:1,depth:1))
    e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    return Array(UnsafeBufferPointer(start: outB.contents().bindMemory(to: Int32.self, capacity: batch*256), count: batch*256))
}

print("=== MLDSASAMPLE — ExpandA/ExpandS (ML-DSA-65) on Metal vs reference ===\n")
var rng: UInt64 = 0x1234567890ABCDEF
func rb(_ n: Int) -> [UInt8] { (0..<n).map { _ in rng ^= rng<<13; rng ^= rng>>7; rng ^= rng<<17; return UInt8(truncatingIfNeeded: rng) } }

let batch = 4096
// ExpandA
var seedsA = [UInt8](); var refA = [Int32]()
for i in 0..<batch { let sd = rb(32); let nonce = UInt16(i & 0xffff); seedsA += sd; seedsA += [UInt8(nonce & 0xff), UInt8(nonce >> 8)]; refA += polyUniformRef(sd, nonce) }
let gpuA = runSample(pUni, &seedsA, 34, batch)
print("ExpandA poly_uniform (\(batch) polys) : \(gpuA == refA ? "PASS" : "FAIL")")
// ExpandS
var seedsS = [UInt8](); var refS = [Int32]()
for i in 0..<batch { let sd = rb(64); let nonce = UInt16(i & 0xffff); seedsS += sd; seedsS += [UInt8(nonce & 0xff), UInt8(nonce >> 8)]; refS += polyUniformEtaRef(sd, nonce) }
let gpuS = runSample(pEta, &seedsS, 66, batch)
print("ExpandS poly_uniform_eta (\(batch) polys) : \(gpuS == refS ? "PASS" : "FAIL")")
