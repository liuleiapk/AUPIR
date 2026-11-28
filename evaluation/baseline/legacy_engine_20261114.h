// Real FSS / libOTe adapter. Private process state is never exported to C.
#include "DCFClient.h"
#include "DCFServer.h"
// Forward declarations avoid duplicated inline modular helpers in upstream headers.
namespace osuCrypto {
class DPFClient {public: static void keyGenDPF(uint128_t,uint128_t,block,block*,uint128_t*,block*,uint128_t*,u64,uint64_t,bool,uint128_t);};
class DPFServer {public: static uint128_t evalOneDPF(uint128_t,block*,uint128_t*,u64,uint8_t,uint64_t,bool,uint128_t);};
}
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <fstream>
#include <iostream>
#include <numeric>
#include "../../epbkpir/matching/dcf_bit_eval.h"
using namespace osuCrypto;
using Bytes=std::vector<uint8_t>;
template<class T> void put(std::ostream& f,const T& x){f.write((const char*)&x,sizeof x);if(!f)throw std::runtime_error("write");}
template<class T> T get(std::istream& f){T x{};f.read((char*)&x,sizeof x);if(!f)throw std::runtime_error("read");return x;}
struct Key {uint32_t bits,op; std::vector<block> k;std::vector<uint128_t> v;};
void save(std::ostream& f,Key& k){put(f,k.bits);put(f,k.op);for(auto x:k.k)put(f,x);for(auto x:k.v)put(f,(uint64_t)x);}
Key load(std::istream& f){Key k;k.bits=get<uint32_t>(f);k.op=get<uint32_t>(f);if(k.bits<1||k.bits>32||k.op>2)throw std::runtime_error("key domain");k.k.resize(k.bits+1);k.v.resize(k.bits+1);for(auto& x:k.k)x=get<block>(f);for(auto& x:k.v)x=get<uint64_t>(f);return k;}
// Shared retrieval-only interface used by the protocol and the benchmark.
Bytes evaluate_atom(Key& k,const std::vector<std::vector<uint64_t>>& rows,size_t column,int sid){
 Bytes z(rows.size());
 if(k.op){
  // One key per predicate, one full-width evaluation per real row. No dedup.
  std::vector<uint32_t> points(rows.size());
  for(size_t i=0;i<rows.size();++i){auto x=rows[i].at(column);if(x>=(1ULL<<k.bits))throw std::runtime_error("attribute domain");if(k.op==2)x=((1ULL<<k.bits)-1)-x;points[i]=static_cast<uint32_t>(x);}
  ipbm::DcfBitEvaluator evaluator(k.bits,k.k.data(),k.v.data());
  evaluator.evaluate_all(points.data(),points.size(),z.data());
 }else for(size_t i=0;i<rows.size();++i){auto x=rows[i].at(column);if(x>=(1ULL<<k.bits))throw std::runtime_error("attribute domain");z[i]=static_cast<uint64_t>(DPFServer::evalOneDPF(uint128_t(x)<<7,k.k.data(),k.v.data(),k.bits,sid,1,true,2))&1;}
 return z;
}
uint8_t bit(block b){return _mm_cvtsi128_si64(b)&1;}
// Both directions have independent, genuine base OTs. Each extension consumes
// fresh PRG output; one random OT per 16-byte segment of chosen messages.
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
 Bytes land(const Bytes& x,const Bytes& y){
  size_t n=x.size();Bytes a(n),b(n),c(n);rng.get(a.data(),n);rng.get(b.data(),n);for(size_t i=0;i<n;++i){a[i]&=1;b[i]&=1;}
  auto u=cross(0,b,a,1),v=cross(1,b,a,1);
  Bytes open(2*n),peer(2*n);for(size_t i=0;i<n;++i){c[i]=(a[i]&b[i])^u[i]^v[i];open[i]=x[i]^a[i];open[n+i]=y[i]^b[i];}
  if(!sid){send(open);recv(peer);}else{recv(peer);send(open);}
  Bytes z(n);for(size_t i=0;i<n;++i){uint8_t e=open[i]^peer[i],f=open[n+i]^peer[n+i];z[i]=(c[i]^(e&b[i])^(f&a[i])^(!sid?(e&f):0))&1;}return z;
 }
};
int main(int argc,char**argv){try{
 std::string cmd=argv[1];
 if(cmd=="keygen"){
  std::ifstream spec(argv[2]);std::ofstream f0(std::string(argv[3])+".0",std::ios::binary),f1(std::string(argv[3])+".1",std::ios::binary);uint32_t count;spec>>count;put(f0,count);put(f1,count);PRNG rng(sysRandomSeed());
  for(unsigned i=0;i<count;++i){uint32_t bits,op;uint64_t target;spec>>bits>>op>>target;if(!spec||bits<1||bits>32||target>=(1ULL<<bits)||op>2)throw std::runtime_error("query domain");
   Key a{bits,op},b{bits,op};a.k.resize(bits+1);b.k.resize(bits+1);a.v.resize(bits+1);b.v.resize(bits+1);
   if(op==2)target=((1ULL<<bits)-1)-target;
   if(!op)DPFClient::keyGenDPF(uint128_t(target)<<7,1,rng.get<block>(),a.k.data(),a.v.data(),b.k.data(),b.v.data(),bits,1,true,2);
   else DCFClient::keyGenDCFMAC(uint128_t(target)<<7,1,rng.get<block>(),a.k.data(),a.v.data(),b.k.data(),b.v.data(),bits,1,true,2,false);
   save(f0,a);save(f1,b);
  }return 0;
 }
 if(cmd!="server")throw std::runtime_error("command");
 int sid=std::stoi(argv[2]);std::string dir=argv[3];
 std::ifstream cfg(dir+"/template");size_t n,fields,atoms,gates,width;cfg>>n>>fields>>atoms>>gates>>width;
 std::vector<unsigned> columns(atoms);for(auto& x:columns)cfg>>x;
 struct Gate{std::string op;size_t a,b;};std::vector<Gate> gs(gates);for(auto& g:gs)cfg>>g.op>>g.a>>g.b;
 if(!cfg||!n||width%16)throw std::runtime_error("template");
 std::ifstream table(dir+"/table");std::vector<std::vector<uint64_t>> rows(n,std::vector<uint64_t>(fields));for(auto& row:rows)for(auto& x:row)table>>x;if(!table)throw std::runtime_error("table");
 std::ifstream keyfile(dir+"/query",std::ios::binary);if(get<uint32_t>(keyfile)!=atoms)throw std::runtime_error("atoms");
 std::vector<Bytes> vectors;
 for(size_t a=0;a<atoms;++a){Key k=load(keyfile);vectors.push_back(evaluate_atom(k,rows,columns[a],sid));}
 IOService io;Session session(io,argv[4],sid?SessionMode::Client:SessionMode::Server,"boolean-v1");auto channel=session.addChannel();Protocol p(sid,channel);
 for(auto& g:gs){auto a=vectors.at(g.a);auto b=vectors.at(g.b);Bytes z(n);if(g.op=="AND"||g.op=="OR"){z=p.land(a,b);if(g.op=="OR")for(size_t i=0;i<n;++i)z[i]^=a[i]^b[i];}else if(g.op=="XOR")for(size_t i=0;i<n;++i)z[i]=a[i]^b[i];else if(g.op=="NOT"){z=a;if(!sid)for(auto& x:z)x^=1;}else throw std::runtime_error("gate");vectors.push_back(z);}
 auto z=std::move(vectors.back());vectors.clear();rows.clear();Bytes d(n*width);std::ifstream desc(dir+"/descriptions",std::ios::binary);desc.read((char*)d.data(),d.size());if(!desc)throw std::runtime_error("description");
 auto u=p.cross(0,z,d,width),v=p.cross(1,z,d,width);for(size_t i=0;i<n;++i)for(size_t j=0;j<width;++j)d[i*width+j]=(z[i]?d[i*width+j]:0)^u[i*width+j]^v[i*width+j];
 // Shared fresh seed is server-only, used for permutation and PIR masks.
 block seed;if(!sid){seed=p.rng.get<block>();channel.send(&seed,1);}else channel.recv(&seed,1);PRNG shuffle(seed);
 std::vector<size_t> perm(n);std::iota(perm.begin(),perm.end(),0);for(size_t i=n;i>1;--i){uint64_t r,limit=uint64_t(-1)-uint64_t(-1)%i;do{r=shuffle.get<uint64_t>();}while(r>=limit);std::swap(perm[i-1],perm[r%i]);}
 std::ofstream out(dir+"/selected",std::ios::binary);for(auto i:perm)out.write((char*)d.data()+i*width,width);out.close();
 // Seed remains in this process; consume one fixed key request, invoke existing
 // backend in a child process, mask all response bytes before exposing to C.
 std::cout<<"READY"<<std::endl;std::string ack;std::getline(std::cin,ack);if(ack!="PIR")throw std::runtime_error("PIR trigger");
 std::ifstream command(dir+"/backend-command");std::string line;std::getline(command,line);if(std::system(line.c_str()))throw std::runtime_error("backend failure");
 std::ifstream raw(dir+"/raw-response",std::ios::binary);std::ofstream masked(dir+"/response",std::ios::binary);char buf[65536];PRNG mask(seed ^ toBlock(0x5049524d41534bULL,0x7631));uint64_t bytes=0;
 while(raw){raw.read(buf,sizeof buf);auto k=raw.gcount();Bytes pad(k);mask.get(pad.data(),k);for(size_t i=0;i<(size_t)k;++i)buf[i]^=pad[i];masked.write(buf,k);bytes+=k;}masked.close();
 std::cout<<"{\"peer_sent_bytes\":"<<channel.getTotalDataSent()<<",\"peer_received_bytes\":"<<channel.getTotalDataRecv()<<",\"chosen_ot_sent_messages\":"<<p.sent<<",\"chosen_ot_received_messages\":"<<p.received<<",\"description_count\":"<<n<<",\"description_bytes\":"<<n*width<<",\"pir_response_bytes\":"<<bytes<<"}"<<std::endl;
 channel.close();session.stop();io.stop();return 0;
 }catch(std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
