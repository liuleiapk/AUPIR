#pragma once
// Production IPBM retrieval. No DPF or public query-operator dispatch.
#include "DCFClient.h"
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <numeric>
#include <map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include "dcf_bit_eval.h"
using namespace osuCrypto;
using Bytes=std::vector<uint8_t>;
template<class T> void put(std::ostream& f,const T& x){f.write((const char*)&x,sizeof x);if(!f)throw std::runtime_error("write");}
template<class T> T get(std::istream& f){T x{};f.read((char*)&x,sizeof x);if(!f)throw std::runtime_error("read");return x;}
using Clock=std::chrono::steady_clock;
inline double elapsed(Clock::time_point t){return std::chrono::duration<double>(Clock::now()-t).count();}
inline double cpu(){timespec t;clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t);return t.tv_sec+t.tv_nsec*1e-9;}
struct Metrics:std::map<std::string,double>{
 using std::map<std::string,double>::map;
 std::string json()const{std::ostringstream o;o<<std::setprecision(17)<<"{";bool first=true;for(auto& v:*this){if(!first)o<<",";first=false;o<<"\""<<v.first<<"\":"<<v.second;}o<<"}";return o.str();}
};
inline void sync_peer(Channel& ch,int sid){uint8_t a=0,b=0;if(!sid){ch.send(&a,1);ch.recv(&b,1);}else{ch.recv(&b,1);ch.send(&a,1);}}
struct Protocol {
 int sid;Channel ch;PRNG rng{sysRandomSeed()};IknpOtExtSender sender;IknpOtExtReceiver receiver;
 uint64_t sent=0,received=0;
 Protocol(int s,Channel c):sid(s),ch(c){if(!sid){sender.genBaseOts(rng,ch);receiver.genBaseOts(rng,ch);}else{receiver.genBaseOts(rng,ch);sender.genBaseOts(rng,ch);}}
 void send(Bytes& b){ch.send(b.data(),b.size());++sent;}
 void recv(Bytes& b){ch.recv(b.data(),b.size());++received;}
 // Returns local shares of a_sender * b_receiver, with arbitrary width b.
 Bytes cross(int who,const Bytes& choices,const Bytes& data,size_t width){
  size_t n=choices.size(), chunks=(width+15)/16,m=n*chunks;Bytes out(n*width);
  if(sid==who){
   std::vector<std::array<block,2>> pads(m);sender.send(pads,rng,ch);
   Bytes wire(m*32);rng.get(out.data(),out.size());
   for(size_t i=0;i<n;++i)for(size_t j=0;j<chunks;++j){size_t at=i*chunks+j;
    uint8_t p[2][16];memcpy(p,pads[at].data(),32);
    for(size_t b=0;b<16;++b){size_t k=j*16+b;uint8_t r=k<width?out[i*width+k]:0,d=k<width?data[i*width+k]:0;
     wire[at*32+b]=p[0][b]^r;wire[at*32+16+b]=p[1][b]^r^d;}}
   send(wire);
  }else{
   BitVector c(m);for(size_t i=0;i<n;++i)for(size_t j=0;j<chunks;++j)c[i*chunks+j]=choices[i];
   std::vector<block> pads(m);receiver.receive(c,pads,rng,ch);Bytes wire(m*32);recv(wire);
   for(size_t i=0;i<n;++i)for(size_t j=0;j<chunks;++j){uint8_t p[16];memcpy(p,&pads[i*chunks+j],16);for(size_t b=0;b<16&&j*16+b<width;++b)out[i*width+j*16+b]=p[b]^wire[(i*chunks+j)*32+choices[i]*16+b];}
  }return out;
 }
};

struct PublicTemplate {
 size_t n,fields,width;
 std::vector<std::pair<uint32_t,uint32_t>> atoms; // column, bits
 std::vector<std::pair<uint32_t,uint32_t>> gates; // references only
 static PublicTemplate read(std::istream& in){
  PublicTemplate t;std::string magic;size_t p,g;in>>magic>>t.n>>t.fields>>p>>g>>t.width;
  if(!in||magic!="IPBM2"||!t.n||!t.fields||!p||t.width%16)throw std::runtime_error("public template");
  t.atoms.resize(p);t.gates.resize(g);
  for(auto& a:t.atoms){in>>a.first>>a.second;if(a.first>=t.fields||a.second<1||a.second>32)throw std::runtime_error("field domain");}
  for(size_t j=0;j<g;++j){auto& v=t.gates[j];in>>v.first>>v.second;if(v.first>=p+j||v.second>=p+j)throw std::runtime_error("gate reference");}
  if(!in)throw std::runtime_error("template truncated");return t;
 }
};
struct DcfKey {std::vector<block> k;std::vector<uint128_t> v;};
inline DcfKey read_dcf(std::istream& in,unsigned bits){
 DcfKey k;k.k.resize(bits+1);k.v.resize(bits+1);
 for(auto& x:k.k)x=get<block>(in);for(auto& x:k.v){x=get<uint64_t>(in);if(x>1)throw std::runtime_error("DCF not generated over GF(2)");}return k;
}
inline void write_dcf(std::ostream& out,const DcfKey& k){for(auto x:k.k)put(out,x);for(auto x:k.v)put(out,uint64_t(x));}
inline std::array<DcfKey,2> generate_dcf(unsigned bits,uint64_t threshold,uint8_t beta,bool gt,PRNG& rng){
 if(bits<1||bits>32||threshold>=(1ULL<<bits)||beta>1)throw std::runtime_error("DCF domain");
 std::array<DcfKey,2> keys;for(auto& k:keys){k.k.resize(bits+1);k.v.resize(bits+1);}
 if(gt)threshold=((1ULL<<bits)-1)-threshold;
 DCFClient::keyGenDCFMAC(uint128_t(threshold)<<7,beta,rng.get<block>(),keys[0].k.data(),keys[0].v.data(),keys[1].k.data(),keys[1].v.data(),bits,1,true,2,false);
 return keys;
}
inline Metrics generate_query(std::istream& spec,std::ostream& s0,std::ostream& s1){
 auto start=Clock::now();auto cp=cpu();uint32_t p,g;spec>>p>>g;if(!spec||!p)throw std::runtime_error("spec header");
 PRNG rng(sysRandomSeed());std::ostream* out[]={&s0,&s1};
 for(auto f:out){put(*f,uint32_t(0x32425049));put(*f,p);put(*f,g);}
 for(size_t j=0;j<p;++j){uint32_t col,bits,a,b,c;uint64_t gt,lt;spec>>col>>bits>>gt>>a>>lt>>b>>c;
  if(!spec||a>1||b>1||c>1)throw std::runtime_error("private condition");
  // Always generate both slots, including zero payloads and constant predicates.
  auto high=generate_dcf(bits,gt,a,true,rng),low=generate_dcf(bits,lt,b,false,rng);uint8_t r=rng.get<uint8_t>()&1;
  for(int sid=0;sid<2;++sid){put(*out[sid],col);put(*out[sid],bits);write_dcf(*out[sid],high[sid]);write_dcf(*out[sid],low[sid]);put(*out[sid],uint8_t(r^(sid?c:0)));}
 }
 for(size_t j=0;j<g;++j){uint32_t a,b,delta;spec>>a>>b>>delta;if(!spec||delta>1||a>=p+j||b>=p+j)throw std::runtime_error("private gate");uint8_t r=rng.get<uint8_t>()&1;
  for(int sid=0;sid<2;++sid){put(*out[sid],a);put(*out[sid],b);put(*out[sid],uint8_t(r^(sid?delta:0)));}}
 s0.flush();s1.flush();return {{"keygen_seconds",elapsed(start)},{"keygen_cpu_seconds",cpu()-cp},{"dcf_key_pairs",double(2*p)}};
}

// Same GF(2) Beaver construction as the previously validated Protocol::land.
// The triple is now explicitly prepared, then consumed exactly once.
struct Triple {
 Bytes a,b,c;
 Triple(size_t n):a(n),b(n),c(n){}
 Triple(Triple&&)=default;Triple& operator=(Triple&&)=default;
 Triple(const Triple&)=delete;Triple& operator=(const Triple&)=delete;
};
inline Triple fresh(Protocol& p,size_t n){
 Triple t(n);p.rng.get(t.a.data(),n);p.rng.get(t.b.data(),n);for(size_t i=0;i<n;++i){t.a[i]&=1;t.b[i]&=1;}
 auto u=p.cross(0,t.b,t.a,1),v=p.cross(1,t.b,t.a,1);
 for(size_t i=0;i<n;++i)t.c[i]=(t.a[i]&t.b[i])^u[i]^v[i];return t;
}
inline Bytes multiply(Protocol& p,const Bytes& x,const Bytes& y,Triple t){
 size_t n=x.size();if(t.a.size()!=n||y.size()!=n)throw std::runtime_error("triple size/reuse");Bytes open(2*n),peer(2*n),z(n);
 for(size_t i=0;i<n;++i){open[i]=x[i]^t.a[i];open[n+i]=y[i]^t.b[i];}
 if(!p.sid){p.send(open);p.recv(peer);}else{p.recv(peer);p.send(open);}
 for(size_t i=0;i<n;++i){auto e=open[i]^peer[i],f=open[n+i]^peer[n+i];z[i]=(t.c[i]^(e&t.b[i])^(f&t.a[i])^(!p.sid?(e&f):0))&1;}return z;
}

// CountOT from the audited candidate: unchanged arithmetic/OT messages, with
// explicit lifecycle checks. Only the aggregate is opened; z is const input.
struct CountOT {
 std::vector<std::array<block,2>> pads;std::vector<block> selected;BitVector choices;bool ready=false;size_t size=0;
 void prepare(Protocol& p,size_t n){
  if(ready)throw std::runtime_error("unconsumed count OT");size=n;
  if(!p.sid){pads.resize(n);p.sender.send(pads,p.rng,p.ch);}else{choices.resize(n);choices.randomize(p.rng);selected.resize(n);p.receiver.receive(choices,selected,p.rng,p.ch);}ready=true;
 }
 uint64_t count(Protocol& p,const Bytes& z){
  size_t n=z.size();if(!ready||n!=size)throw std::runtime_error("missing/fresh count OT");ready=false;
  Bytes delta(n),wire(16*n);uint64_t prod=0;
  if(p.sid){for(size_t i=0;i<n;++i)delta[i]=choices[i]^z[i];p.send(delta);p.recv(wire);
   for(size_t i=0;i<n;++i){uint64_t w,mask;memcpy(&w,wire.data()+16*i+8*z[i],8);memcpy(&mask,&selected[i],8);prod+=w^mask;}}
  else{p.recv(delta);for(size_t i=0;i<n;++i){auto r=p.rng.get<uint64_t>();prod+=r;for(unsigned j=0;j<2;++j){uint64_t mask,w=(j?uint64_t(z[i]):0)-r;memcpy(&mask,&pads[i][j^delta[i]],8);w^=mask;memcpy(wire.data()+16*i+8*j,&w,8);}}p.send(wire);}
  uint64_t share=0;for(auto b:z)share+=b;share-=2*prod;
  Bytes a(8),b(8);memcpy(a.data(),&share,8);if(!p.sid){p.send(a);p.recv(b);}else{p.recv(b);p.send(a);}uint64_t other;memcpy(&other,b.data(),8);
  pads.clear();selected.clear();choices.resize(0);auto m=share+other;if(m>n)throw std::runtime_error("count outside N");return m;
 }
};

struct RetrievalSession {
 Protocol& p;const PublicTemplate& t;std::vector<Triple> triples;CountOT count_ot;bool ready=false;uint64_t epoch=0;
 RetrievalSession(Protocol& protocol,const PublicTemplate& shape):p(protocol),t(shape){}
 Metrics prepare(){
  if(ready)throw std::runtime_error("unconsumed retrieval materials");auto start=Clock::now();auto cp=cpu();auto sent=p.ch.getTotalDataSent();
  for(size_t j=0;j<t.gates.size();++j)triples.push_back(fresh(p,t.n));sync_peer(p.ch,p.sid);
  double triple_s=elapsed(start);auto triple_bytes=p.ch.getTotalDataSent()-sent;auto tick=Clock::now();sent=p.ch.getTotalDataSent();
  count_ot.prepare(p,t.n);sync_peer(p.ch,p.sid);double cot_s=elapsed(tick);auto cot_bytes=p.ch.getTotalDataSent()-sent;ready=true;++epoch;
  return {{"preprocessing_seconds",elapsed(start)},{"triple_seconds",triple_s},{"triple_sent_bytes",double(triple_bytes)},
   {"count_random_ot_seconds",cot_s},{"count_random_ot_sent_bytes",double(cot_bytes)},{"cpu_seconds",cpu()-cp},
   {"fresh_boolean_triples",double(t.n*t.gates.size())},{"fresh_count_random_ots",double(t.n)},{"material_epoch",double(epoch)}};
 }
 struct Result {Bytes z;uint64_t m;Metrics metrics;};
 Result evaluate(const std::string& blob,const std::vector<std::vector<uint64_t>>& rows){
  if(!ready||rows.size()!=t.n)throw std::runtime_error("no fresh retrieval materials");ready=false;
  auto start=Clock::now();auto cp=cpu();std::istringstream in(blob);if(get<uint32_t>(in)!=0x32425049||get<uint32_t>(in)!=t.atoms.size()||get<uint32_t>(in)!=t.gates.size())throw std::runtime_error("query version/shape");
  std::vector<Bytes> vectors;vectors.reserve(t.atoms.size()+t.gates.size());double eval_s=0;auto eval_cp=cpu();
  for(auto& shape:t.atoms){auto col=get<uint32_t>(in),bits=get<uint32_t>(in);if(col!=shape.first||bits!=shape.second)throw std::runtime_error("query field template mismatch");
   auto gt=read_dcf(in,bits),lt=read_dcf(in,bits);uint8_t c=get<uint8_t>(in);if(c>1)throw std::runtime_error("constant share");auto tick=Clock::now();
   std::vector<uint32_t> high(t.n),low(t.n);const uint64_t upper=(1ULL<<bits)-1;
   for(size_t i=0;i<t.n;++i){auto x=rows[i].at(col);if(x>upper)throw std::runtime_error("attribute domain");high[i]=upper-x;low[i]=x;}
   Bytes a(t.n),b(t.n);ipbm::DcfBitEvaluator(bits,gt.k.data(),gt.v.data()).evaluate_all(high.data(),t.n,a.data());
   ipbm::DcfBitEvaluator(bits,lt.k.data(),lt.v.data()).evaluate_all(low.data(),t.n,b.data());
   for(size_t i=0;i<t.n;++i)a[i]^=b[i]^c;eval_s+=elapsed(tick);vectors.push_back(std::move(a));
  }
  double eval_cpu=cpu()-eval_cp;auto boolean_cp=cpu();auto tick=Clock::now();auto sent=p.ch.getTotalDataSent();
  for(size_t j=0;j<t.gates.size();++j){auto ai=get<uint32_t>(in),bi=get<uint32_t>(in);auto delta=get<uint8_t>(in);
   if(std::make_pair(ai,bi)!=t.gates[j]||delta>1)throw std::runtime_error("gate template/share");
   auto a=vectors.at(ai),b=vectors.at(bi);for(size_t i=0;i<t.n;++i){a[i]^=delta;b[i]^=delta;}
   auto z=multiply(p,a,b,std::move(triples[j]));for(auto& v:z)v^=delta;vectors.push_back(std::move(z));
  }
  triples.clear();if(in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("query trailing bytes");
  double boolean_s=elapsed(tick),boolean_cpu=cpu()-boolean_cp;auto boolean_bytes=p.ch.getTotalDataSent()-sent;Bytes z=std::move(vectors.back());
  tick=Clock::now();auto count_cp=cpu();sent=p.ch.getTotalDataSent();auto m=count_ot.count(p,z);double count_s=elapsed(tick),count_cpu=cpu()-count_cp;auto count_bytes=p.ch.getTotalDataSent()-sent;
  Metrics metrics{{"evaluation_seconds",eval_s},{"boolean_seconds",boolean_s},{"boolean_sent_bytes",double(boolean_bytes)},
   {"count_seconds",count_s},{"count_sent_bytes",double(count_bytes)},{"server_retrieval_seconds",elapsed(start)},
   {"cpu_seconds",cpu()-cp},{"evaluation_cpu_seconds",eval_cpu},{"boolean_cpu_seconds",boolean_cpu},{"count_cpu_seconds",count_cpu},{"m",double(m)},{"query_bytes",double(blob.size()+5)},
   {"dcf_evaluations",double(2*t.n*t.atoms.size())},{"boolean_rounds",double(t.gates.size())},{"count_dependency_rounds",3},{"material_epoch",double(epoch)}};
  return {std::move(z),m,std::move(metrics)};
 }
};
