// MLDSASIGNPRIM — ML-DSA-65 Sign/Verify primitives on Metal, validated vs reference:
//   decompose / make_hint / use_hint (GAMMA2=(Q-1)/32), SampleInBall (poly_challenge),
//   ExpandMask (poly_uniform_gamma1 + polyz_unpack, GAMMA1=2^19).
// Build: swiftc -O MLDSASIGNPRIM.swift -o mldsa_signprim -framework Metal -framework Foundation

import Foundation
import Metal

let Q: Int32 = 8380417, GAMMA2: Int32 = (8380417-1)/32, GAMMA1: Int32 = 1<<19, TAU = 49, CT = 48
// ---- keccak ref ----
let RHO=[1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44]
let PIL=[10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1]
let RC:[UInt64]=[0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
func rotl(_ x:UInt64,_ n:Int)->UInt64{ n==0 ? x : (x<<n)|(x>>(64-n)) }
func keccakf(_ a:inout [UInt64]){ for r in 0..<24 { var b=[UInt64](repeating:0,count:5); for i in 0..<5{b[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20]}; for i in 0..<5{let t=b[(i+4)%5]^rotl(b[(i+1)%5],1); var j=0; while j<25{a[j+i]^=t;j+=5}}; var t=a[1]; for i in 0..<24{let j=PIL[i];let tmp=a[j];a[j]=rotl(t,RHO[i]);t=tmp}; var j=0; while j<25{var c=[UInt64](repeating:0,count:5); for i in 0..<5{c[i]=a[j+i]}; for i in 0..<5{a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5])}; j+=5}; a[0]^=RC[r] } }
func absorb(_ inp:[UInt8], _ rate:Int)->[UInt64]{ var s=[UInt64](repeating:0,count:25); var off=0,rem=inp.count; while rem>=rate{ for i in 0..<(rate/8){var v:UInt64=0; for b in 0..<8{v|=UInt64(inp[off+8*i+b])<<(8*b)}; s[i]^=v}; off+=rate; rem-=rate; keccakf(&s)}; for i in 0..<rem{s[i/8]^=UInt64(inp[off+i])<<(8*(i%8))}; s[rem/8]^=UInt64(0x1F)<<(8*(rem%8)); s[(rate-1)/8]^=UInt64(1)<<63; return s }
func blk(_ s:[UInt64],_ rate:Int)->[UInt8]{ var b=[UInt8](); for i in 0..<(rate/8){let v=s[i]; for j in 0..<8{b.append(UInt8((v>>(8*j))&0xff))}}; return b }

func decomposeRef(_ a:Int32)->(Int32,Int32){ var a1=(a+127)>>7; a1=(a1&*1025+(1<<21))>>22; a1&=15; var a0=a-a1*2*GAMMA2; a0-=((((Q-1)/2 - a0)>>31)&Q); return (a1,a0) }
func makeHintRef(_ a0:Int32,_ a1:Int32)->Int32{ (a0>GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) ? 1:0 }
func useHintRef(_ a:Int32,_ h:Int32)->Int32{ let (a1,a0)=decomposeRef(a); if h==0{return a1}; return a0>0 ? (a1+1)&15 : (a1-1)&15 }
func challengeRef(_ seed:[UInt8])->[Int32]{ var s=absorb(seed,136); keccakf(&s); var buf=blk(s,136); var signs:UInt64=0; for i in 0..<8{signs|=UInt64(buf[i])<<(8*i)}; var pos=8; var c=[Int32](repeating:0,count:256)
    for i in (256-TAU)..<256 { var b=0; repeat { if pos>=136{keccakf(&s); buf=blk(s,136); pos=0}; b=Int(buf[pos]); pos+=1 } while b>i; c[i]=c[b]; c[b]=1-2*Int32(signs&1); signs>>=1 }; return c }
func expandMaskRef(_ seed:[UInt8], _ nonce:UInt16)->[Int32]{ var s=absorb(seed+[UInt8(nonce&0xff),UInt8(nonce>>8)],136); var buf=[UInt8](); for _ in 0..<5{keccakf(&s); buf+=blk(s,136)}; var r=[Int32](repeating:0,count:256)
    for i in 0..<128 { var c0=Int32(buf[5*i])|(Int32(buf[5*i+1])<<8)|(Int32(buf[5*i+2])<<16); c0 &= 0xFFFFF; var c1=(Int32(buf[5*i+2])>>4)|(Int32(buf[5*i+3])<<4)|(Int32(buf[5*i+4])<<12); c1 &= 0xFFFFF; r[2*i]=GAMMA1-c0; r[2*i+1]=GAMMA1-c1 }; return r }

let kSrc = """
#include <metal_stdlib>
using namespace metal;
constant int Q=8380417, G2=(8380417-1)/32, G1=(1<<19), TAU=49;
constant ulong RC[24]={0x1ul,0x8082ul,0x800000000000808aul,0x8000000080008000ul,0x808bul,0x80000001ul,0x8000000080008081ul,0x8000000000008009ul,0x8aul,0x88ul,0x80008009ul,0x8000000aul,0x8000808bul,0x800000000000008bul,0x8000000000008089ul,0x8000000000008003ul,0x8000000000008002ul,0x8000000000000080ul,0x800aul,0x800000008000000aul,0x8000000080008081ul,0x8000000000008080ul,0x80000001ul,0x8000000080008008ul};
constant uint RHt[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
constant uint PIL[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
inline ulong rotl64(ulong x,uint n){return (x<<n)|(x>>(64-n));}
inline void kf(thread ulong* a){ for(int r=0;r<24;++r){ ulong b[5]; for(int i=0;i<5;i++)b[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20]; for(int i=0;i<5;i++){ulong t=b[(i+4)%5]^rotl64(b[(i+1)%5],1); for(int j=0;j<25;j+=5)a[j+i]^=t;} ulong t=a[1]; for(int i=0;i<24;i++){uint j=PIL[i];ulong tm=a[j];a[j]=rotl64(t,RHt[i]);t=tm;} for(int j=0;j<25;j+=5){ulong c[5];for(int i=0;i<5;i++)c[i]=a[j+i];for(int i=0;i<5;i++)a[j+i]=c[i]^((~c[(i+1)%5])&c[(i+2)%5]);} a[0]^=RC[r]; } }
inline void absorb1(thread ulong* s, thread const uchar* in, uint inlen, uint rate){ for(uint i=0;i<25u;i++)s[i]=0; for(uint i=0;i<inlen;i++)s[i/8u]^=(ulong)in[i]<<(8u*(i%8u)); s[inlen/8u]^=(ulong)0x1F<<(8u*(inlen%8u)); s[(rate-1u)/8u]^=(ulong)1<<63; }
inline int decompose(int a, thread int* a0){ int a1=(a+127)>>7; a1=(a1*1025+(1<<21))>>22; a1&=15; int r=a-a1*2*G2; r-=(((Q-1)/2 - r)>>31)&Q; *a0=r; return a1; }
kernel void k_decompose(device const int* ina [[buffer(0)]], device int* a1o [[buffer(1)]], device int* a0o [[buffer(2)]], device int* hintchk [[buffer(3)]], uint gid [[thread_position_in_grid]]){
    int a0; int a1=decompose(ina[gid], &a0); a1o[gid]=a1; a0o[gid]=a0;
    int h=(a0>G2 || a0<-G2 || (a0==-G2 && a1!=0))?1:0; hintchk[gid]=h;
}
kernel void k_usehint(device const int* ina [[buffer(0)]], device const int* hint [[buffer(1)]], device int* out [[buffer(2)]], uint gid [[thread_position_in_grid]]){
    int a0; int a1=decompose(ina[gid], &a0); int h=hint[gid]; out[gid] = (h==0)?a1:(a0>0?((a1+1)&15):((a1-1)&15));
}
kernel void k_challenge(device const uchar* seeds [[buffer(0)]], device int* out [[buffer(1)]], constant uint& cstride [[buffer(2)]], uint gid [[thread_position_in_grid]]){
    uchar sd[48]; for(uint i=0;i<48u;i++) sd[i]=seeds[gid*cstride+i];
    ulong s[25]; absorb1(s, sd, 48u, 136u); kf(s);
    uchar buf[136]; for(uint i=0;i<17u;i++){ulong v=s[i]; for(uint b=0;b<8u;b++)buf[8u*i+b]=(uchar)(v>>(8u*b));}
    ulong signs=0; for(uint i=0;i<8u;i++) signs|=(ulong)buf[i]<<(8u*i); uint pos=8u;
    uint ob=gid*256u; for(uint i=0;i<256u;i++) out[ob+i]=0;
    for(uint i=256u-TAU; i<256u; i++){ uint b;
        do { if(pos>=136u){ kf(s); for(uint k=0;k<17u;k++){ulong v=s[k]; for(uint q=0;q<8u;q++)buf[8u*k+q]=(uchar)(v>>(8u*q));} pos=0; } b=buf[pos++]; } while(b>i);
        out[ob+i]=out[ob+b]; out[ob+b]=1-2*(int)(signs&1); signs>>=1; }
}
kernel void k_expandmask(device const uchar* seeds [[buffer(0)]], device int* out [[buffer(1)]], constant uint& sstride [[buffer(2)]], uint gid [[thread_position_in_grid]]){
    uchar sd[66]; for(uint i=0;i<66u;i++) sd[i]=seeds[gid*sstride+i];
    ulong s[25]; absorb1(s, sd, 66u, 136u);
    uchar buf[680]; for(uint blk=0;blk<5u;blk++){ kf(s); for(uint k=0;k<17u;k++){ulong v=s[k]; for(uint q=0;q<8u;q++)buf[blk*136u+8u*k+q]=(uchar)(v>>(8u*q));} }
    uint ob=gid*256u;
    for(uint i=0;i<128u;i++){ int c0=(int)buf[5*i]|((int)buf[5*i+1]<<8)|((int)buf[5*i+2]<<16); c0&=0xFFFFF; int c1=((int)buf[5*i+2]>>4)|((int)buf[5*i+3]<<4)|((int)buf[5*i+4]<<12); c1&=0xFFFFF; out[ob+2*i]=G1-c0; out[ob+2*i+1]=G1-c1; }
}
"""

let dev = MTLCreateSystemDefaultDevice()!
let queue = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: kSrc, options: nil)
func pso(_ n:String)->MTLComputePipelineState{ try! dev.makeComputePipelineState(function: lib.makeFunction(name:n)!) }
func buf32(_ a:[Int32])->MTLBuffer{ var x=a; return dev.makeBuffer(bytes:&x, length:a.count*4, options:.storageModeShared)! }
func bufU(_ a:[UInt8])->MTLBuffer{ var x=a; return dev.makeBuffer(bytes:&x, length:max(1,a.count), options:.storageModeShared)! }
func empty(_ n:Int)->MTLBuffer{ dev.makeBuffer(length:n*4, options:.storageModeShared)! }
func rd(_ b:MTLBuffer,_ n:Int)->[Int32]{ Array(UnsafeBufferPointer(start:b.contents().bindMemory(to:Int32.self,capacity:n),count:n)) }
func run(_ p:MTLComputePipelineState,_ threads:Int,_ bufs:[MTLBuffer],_ bytes:[(UInt32,Int)]=[]){ let cb=queue.makeCommandBuffer()!; let e=cb.makeComputeCommandEncoder()!; e.setComputePipelineState(p); for (i,b) in bufs.enumerated(){e.setBuffer(b,offset:0,index:i)}; for (v,idx) in bytes{var vv=v; e.setBytes(&vv,length:4,index:idx)}; e.dispatchThreads(MTLSize(width:threads,height:1,depth:1),threadsPerThreadgroup:MTLSize(width:min(256,threads),height:1,depth:1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted() }

print("=== MLDSASIGNPRIM — ML-DSA-65 sign/verify primitives vs reference ===\n")
var rng:UInt64 = 0x55AA55AA12345678
func r32()->Int32{ rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return Int32(truncatingIfNeeded:rng) }
func rby(_ n:Int)->[UInt8]{ (0..<n).map{_ in rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return UInt8(truncatingIfNeeded:rng)} }

// decompose / make_hint / use_hint
let M = 1<<20
var ina=[Int32](repeating:0,count:M); for i in 0..<M{ var v=r32()%Q; if v<0{v+=Q}; ina[i]=v }
let inB=buf32(ina), a1B=empty(M), a0B=empty(M), hcB=empty(M)
run(pso("k_decompose"), M, [inB,a1B,a0B,hcB])
let a1g=rd(a1B,M), a0g=rd(a0B,M), hcg=rd(hcB,M)
var dOK=true,hOK=true; for i in 0..<M { let (a1,a0)=decomposeRef(ina[i]); if a1g[i] != a1 || a0g[i] != a0 {dOK=false;break}; if hcg[i] != makeHintRef(a0,a1){hOK=false;break} }
print("decompose (\(M) samples)      : \(dOK ? "PASS":"FAIL")")
print("make_hint (\(M) samples)      : \(hOK ? "PASS":"FAIL")")
var hints=[Int32](repeating:0,count:M); for i in 0..<M{hints[i]=r32()&1}
let hB=buf32(hints), uhB=empty(M)
run(pso("k_usehint"), M, [inB,hB,uhB])
let uhg=rd(uhB,M); var uOK=true; for i in 0..<M where uhg[i] != useHintRef(ina[i],hints[i]){uOK=false;break}
print("use_hint (\(M) samples)       : \(uOK ? "PASS":"FAIL")")

// SampleInBall
let nb=4096
var cseeds=[UInt8](); for _ in 0..<nb{ cseeds += rby(48) }
let csB=bufU(cseeds), coB=empty(nb*256)
run(pso("k_challenge"), nb, [csB,coB], [(UInt32(48),2)])
let cg=rd(coB,nb*256); var cOK=true; for i in 0..<nb { let ref=challengeRef(Array(cseeds[i*48..<(i+1)*48])); if Array(cg[i*256..<(i+1)*256]) != ref {cOK=false;break} }
print("SampleInBall (\(nb) challenges): \(cOK ? "PASS":"FAIL")")

// ExpandMask
var mseeds=[UInt8](); var mref=[Int32](); for i in 0..<nb{ let sd=rby(64); let nonce=UInt16(i & 0xffff); mseeds += sd + [UInt8(nonce&0xff),UInt8(nonce>>8)]; mref += expandMaskRef(sd,nonce) }
let msB=bufU(mseeds), moB=empty(nb*256)
run(pso("k_expandmask"), nb, [msB,moB], [(UInt32(66),2)])
let mg=rd(moB,nb*256); print("ExpandMask (\(nb) polys)       : \(mg == mref ? "PASS":"FAIL")")
