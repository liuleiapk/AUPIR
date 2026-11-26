// Standalone tests only: reveals are confined to this process.
#define main protocol_main_not_called
#include "../../evaluation/baseline/legacy_engine_20261114.h"
#undef main
#include <chrono>
#include <algorithm>

struct Pair {Key a,b;};
Pair generate(unsigned width,uint32_t threshold,PRNG& rng,unsigned op=1){
 Pair pair{Key{width,op},Key{width,op}};
 for(Key* k:{&pair.a,&pair.b}){k->k.resize(width+1);k->v.resize(width+1);}
 DCFClient::keyGenDCFMAC(uint128_t(threshold)<<7,1,rng.get<block>(),pair.a.k.data(),pair.a.v.data(),pair.b.k.data(),pair.b.v.data(),width,1,true,2,false);
 return pair;
}
uint8_t reference(Key& k,uint32_t x,int sid){return static_cast<uint64_t>(DCFServer::evalOneDCFMAC(uint128_t(x)<<7,k.k.data(),k.v.data(),k.bits,sid,1,true,2))&1;}
uint64_t check(Pair& pair,const std::vector<uint32_t>& points,uint32_t threshold){
 std::array<Bytes,2> outputs;
 for(int sid=0;sid<2;++sid){Key& k=sid?pair.b:pair.a;
  // Exercise unchanged serialized key material too.
  std::stringstream wire;save(wire,k);Key decoded=load(wire);
  ipbm::DcfBitEvaluator eval(decoded.bits,decoded.k.data(),decoded.v.data());
  outputs[sid].resize(points.size());eval.evaluate_all(points.data(),points.size(),outputs[sid].data());
  for(size_t i=0;i<points.size();++i){uint8_t scalar;eval.evaluate<1>(&points[i],&scalar);
   if(outputs[sid][i]!=scalar||scalar!=reference(k,points[i],sid))throw std::runtime_error("per-party scalar/batch/reference mismatch");}
 }
 for(size_t i=0;i<points.size();++i)if((outputs[0][i]^outputs[1][i])!=(points[i]<threshold))throw std::runtime_error("strict LT mismatch");
 return points.size();
}
int main(int argc,char** argv){try{
 PRNG rng(sysRandomSeed());uint64_t cases=0;
 for(unsigned width=1;width<=8;++width){std::vector<uint32_t> points(1u<<width);std::iota(points.begin(),points.end(),0);
  for(uint32_t threshold=0;threshold<points.size();++threshold){auto keys=generate(width,threshold,rng);cases+=check(keys,points,threshold);}}
 for(unsigned width=9;width<=32;++width){uint32_t u=static_cast<uint32_t>((uint64_t(1)<<width)-1);
  for(unsigned trial=0;trial<64;++trial){uint32_t t=trial==0?0:trial==1?u:trial==2?32:trial==3?35:rng.get<uint32_t>()&u;
   std::vector<uint32_t> points={0,1,31,32,33,34,35,36,u-1,u,t};if(t)points.push_back(t-1);if(t<u)points.push_back(t+1);
   for(unsigned i=0;i<67;++i)points.push_back(rng.get<uint32_t>()&u);
   for(auto& x:points)x&=u;auto keys=generate(width,t,rng);cases+=check(keys,points,t);
  }
 }
 // Public default API, GT via U-x/U-t and all tail sizes; thresholds 32 and35.
 for(uint32_t t:{0u,32u,35u,0x7fffffffu,0x80000000u,0xffffffffu}){
  for(size_t n:{0u,1u,7u,8u,9u,15u,16u,17u,33u,129u}){
   std::vector<std::vector<uint64_t>> rows(n,std::vector<uint64_t>(1));
   for(size_t i=0;i<n;++i)rows[i][0]=i%2?32u:rng.get<uint32_t>();
   auto pair=generate(32,0xffffffffu-t,rng,2);auto z0=evaluate_atom(pair.a,rows,0,0),z1=evaluate_atom(pair.b,rows,0,1);
   for(size_t i=0;i<n;++i)if((z0[i]^z1[i])!=(rows[i][0]>t))throw std::runtime_error("GT endpoint/tail mismatch");cases+=n;
  }
 }
 std::cout<<"{\"correctness_cases\":"<<cases<<",\"per_party_equivalence\":true,\"status\":\"PASS\"}"<<std::endl;
 // Same-width primitive microbenchmark; full random 32-bit records, no cache.
 const size_t n=10000;std::vector<uint32_t> points(n);for(auto& x:points)x=rng.get<uint32_t>();Bytes output(n);uint64_t guard=0;
 for(unsigned repeat=0;repeat<7;++repeat){
  auto keys=generate(32,32,rng);Key dpf{32,0};Key other{32,0};dpf.k.resize(33);other.k.resize(33);dpf.v.resize(33);other.v.resize(33);
  DPFClient::keyGenDPF(uint128_t(32)<<7,1,rng.get<block>(),dpf.k.data(),dpf.v.data(),other.k.data(),other.v.data(),32,1,true,2);
  ipbm::DcfBitEvaluator fast(32,keys.a.k.data(),keys.a.v.data());
  auto measure=[&](auto fn){auto start=std::chrono::steady_clock::now();fn();for(auto x:output)guard+=x;return std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();};
  double old=measure([&]{for(size_t i=0;i<n;++i)output[i]=reference(keys.a,points[i],0);});
  double scalar=measure([&]{for(size_t i=0;i<n;++i)fast.evaluate<1>(&points[i],&output[i]);});
  double batch=measure([&]{fast.evaluate_all(points.data(),n,output.data());});
  double point=measure([&]{for(size_t i=0;i<n;++i)output[i]=static_cast<uint64_t>(DPFServer::evalOneDPF(uint128_t(points[i])<<7,dpf.k.data(),dpf.v.data(),32,0,1,true,2))&1;});
  std::cout<<"{\"primitive_repeat\":"<<repeat<<",\"n\":"<<n<<",\"width\":32,\"threshold\":32,\"reference_dcf_seconds\":"<<old<<",\"scalar_dcf_seconds\":"<<scalar<<",\"batch_dcf_seconds\":"<<batch<<",\"dpf_seconds\":"<<point<<",\"guard\":"<<guard<<"}"<<std::endl;
 }
 return 0;
 }catch(std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
