// Independent candidates only. Production entry, descriptors and Batch PIR untouched.
#define main production_main
#include "legacy_engine_20261114.h"
#undef main
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <chrono>
#include <ctime>
#include <iomanip>
using Clock=std::chrono::steady_clock;
double elapsed(Clock::time_point t){return std::chrono::duration<double>(Clock::now()-t).count();}
void sync_peer(Channel& ch,int sid){uint8_t a=0,b=0;if(!sid){ch.send(&a,1);ch.recv(&b,1);}else{ch.recv(&b,1);ch.send(&a,1);}}
double cpu(){timespec t;clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t);return t.tv_sec+t.tv_nsec*1e-9;}
void rx(int f,void* q,size_t n){auto p=(char*)q;while(n){auto k=::recv(f,p,n,0);if(k<=0)throw std::runtime_error("client recv");p+=k;n-=k;}}
void tx(int f,const void* q,size_t n){auto p=(const char*)q;while(n){auto k=::send(f,p,n,MSG_NOSIGNAL);if(k<=0)throw std::runtime_error("client send");p+=k;n-=k;}}
// Same GF(2) Beaver construction as Protocol::land, with fresh cross terms
// generated before query upload. Each pool entry is moved/consumed exactly once.
struct Triple{Bytes a,b,c;};
Triple fresh(Protocol& p,size_t n){
 Triple t{Bytes(n),Bytes(n),Bytes(n)};p.rng.get(t.a.data(),n);p.rng.get(t.b.data(),n);
 for(size_t i=0;i<n;++i){t.a[i]&=1;t.b[i]&=1;}
 auto u=p.cross(0,t.b,t.a,1),v=p.cross(1,t.b,t.a,1);
 for(size_t i=0;i<n;++i)t.c[i]=(t.a[i]&t.b[i])^u[i]^v[i];return t;
}
Bytes multiply(Protocol& p,const Bytes& x,const Bytes& y,Triple t){
 size_t n=x.size();if(t.a.size()!=n||y.size()!=n)throw std::runtime_error("triple size/reuse");
 Bytes open(2*n),peer(2*n),z(n);
 for(size_t i=0;i<n;++i){open[i]=x[i]^t.a[i];open[n+i]=y[i]^t.b[i];}
 if(!p.sid){p.send(open);p.recv(peer);}else{p.recv(peer);p.send(open);}
 for(size_t i=0;i<n;++i){auto e=open[i]^peer[i],f=open[n+i]^peer[n+i];z[i]=(t.c[i]^(e&t.b[i])^(f&t.a[i])^(!p.sid?(e&f):0))&1;}return z;
}
// Fresh random OT, independent of query, for arithmetic B2A cross product.
// Online messages are -r and z0-r in Z_(2^64), NOT XOR-masked products.
struct CountOT{
 std::vector<std::array<block,2>> pads;std::vector<block> selected;BitVector choices;
 void prepare(Protocol& p,size_t n){if(!p.sid){pads.resize(n);p.sender.send(pads,p.rng,p.ch);}else{choices.resize(n);choices.randomize(p.rng);selected.resize(n);p.receiver.receive(choices,selected,p.rng,p.ch);}}
 uint64_t count(Protocol& p,const Bytes& z){
  size_t n=z.size();Bytes delta(n),wire(16*n);uint64_t prod=0;
  if(p.sid){for(size_t i=0;i<n;++i)delta[i]=choices[i]^z[i];p.send(delta);p.recv(wire);
   for(size_t i=0;i<n;++i){uint64_t w,mask;memcpy(&w,wire.data()+16*i+8*z[i],8);memcpy(&mask,&selected[i],8);prod+=w^mask;}}
  else{p.recv(delta);for(size_t i=0;i<n;++i){auto r=p.rng.get<uint64_t>();prod+=r;for(unsigned j=0;j<2;++j){uint64_t mask,w=(j?uint64_t(z[i]):0)-r;memcpy(&mask,&pads[i][j^delta[i]],8);w^=mask;memcpy(wire.data()+16*i+8*j,&w,8);}}p.send(wire);}
  uint64_t share=0;for(auto b:z)share+=b;share-=2*prod;
  Bytes a(8),b(8);memcpy(a.data(),&share,8);if(!p.sid){p.send(a);p.recv(b);}else{p.recv(b);p.send(a);}uint64_t other;memcpy(&other,b.data(),8);
  pads.clear();selected.clear();choices.resize(0);auto m=share+other;if(m>n)throw std::runtime_error("count outside N");return m;
 }
};
std::array<int,3> coeff(const std::string& route,const std::string& op){
 // c XOR a*u XOR b*v (A), or c XOR a*LT XOR b*EQ (B).
 if(route=="A"){
  if(op=="GT")return {0,1,0};if(op=="GE")return {1,0,1};if(op=="LT")return {0,0,1};if(op=="LE")return {1,1,0};if(op=="EQ")return {1,1,1};if(op=="NE")return {0,1,1};
 }else{
  if(op=="GT")return {1,1,1};if(op=="GE")return {1,1,0};if(op=="LT")return {0,1,0};if(op=="LE")return {0,1,1};if(op=="EQ")return {0,0,1};if(op=="NE")return {1,0,1};
 }throw std::runtime_error("relation");
}
std::array<int,4> gate_coeff(const std::string& op){
 if(op=="AND")return {0,0,0,1};if(op=="OR")return {0,1,1,1};if(op=="XOR")return {0,1,1,0};if(op=="NOT")return {1,1,0,0};if(op=="ID")return {0,1,0,0};throw std::runtime_error("connector");
}
std::array<Key,2> gen(unsigned bits,unsigned type,uint64_t target,unsigned beta,PRNG& rng){
 std::array<Key,2> k{Key{bits,type},Key{bits,type}};for(auto& a:k){a.k.resize(bits+1);a.v.resize(bits+1);}
 if(type==2)target=((1ULL<<bits)-1)-target;
 if(type==0)DPFClient::keyGenDPF(uint128_t(target)<<7,beta,rng.get<block>(),k[0].k.data(),k[0].v.data(),k[1].k.data(),k[1].v.data(),bits,1,true,2);
 else DCFClient::keyGenDCFMAC(uint128_t(target)<<7,beta,rng.get<block>(),k[0].k.data(),k[0].v.data(),k[1].k.data(),k[1].v.data(),bits,1,true,2,false);
 return k;
}
int main(int argc,char** argv){try{
 std::string cmd=argv[1];
 if(cmd=="keygen"){
  auto start=Clock::now();double cp=cpu();std::string route=argv[2];if(route!="A"&&route!="B")throw std::runtime_error("route");
  std::ifstream spec(argv[3]);std::ofstream f0(std::string(argv[4])+".0",std::ios::binary),f1(std::string(argv[4])+".1",std::ios::binary);std::ostream* fs[]={&f0,&f1};PRNG rng(sysRandomSeed());uint32_t atoms,gates;spec>>atoms>>gates;
  for(auto f:fs){put(*f,atoms);put(*f,gates);}
  for(size_t i=0;i<atoms;++i){uint32_t col,bits;uint64_t threshold;std::string op;spec>>col>>bits>>op>>threshold;if(bits<1||bits>32||threshold>=(1ULL<<bits))throw std::runtime_error("domain");auto c=coeff(route,op);
   auto a=gen(bits,route=="A"?2:1,threshold,c[1],rng),b=gen(bits,route=="A"?1:0,threshold,c[2],rng);uint8_t r=rng.get<uint8_t>()&1;
   for(int sid=0;sid<2;++sid){put(*fs[sid],col);save(*fs[sid],a[sid]);save(*fs[sid],b[sid]);put(*fs[sid],uint8_t(r^(sid?c[0]:0)));}}
  for(size_t i=0;i<gates;++i){uint32_t a,b;std::string op;spec>>op>>a>>b;auto c=gate_coeff(op);for(auto f:fs){put(*f,a);put(*f,b);}for(auto v:c){uint8_t r=rng.get<uint8_t>()&1;put(f0,r);put(f1,uint8_t(r^v));}}
  if(!spec)throw std::runtime_error("spec");f0.close();f1.close();std::cout<<std::setprecision(12)<<"{\"keygen_seconds\":"<<elapsed(start)<<",\"keygen_cpu_seconds\":"<<cpu()-cp<<",\"pairs\":"<<2*atoms<<"}"<<std::endl;return 0;
 }
 if(cmd!="server"||argc!=6)throw std::runtime_error("server sid table peer clientport");int sid=std::stoi(argv[2]);std::ifstream table(argv[3]);size_t n,fields;table>>n>>fields;std::vector<std::vector<uint64_t>> rows(n,std::vector<uint64_t>(fields));for(auto& row:rows)for(auto& x:row)table>>x;if(!table||!n)throw std::runtime_error("table");
 int listener=::socket(AF_INET,SOCK_STREAM,0),yes=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(std::stoi(argv[5]));if(bind(listener,(sockaddr*)&addr,sizeof addr)||listen(listener,1))throw std::runtime_error("listen");
 IOService io(1);Session session(io,argv[4],sid?SessionMode::Client:SessionMode::Server,"ipbm-baseline-v1");auto ch=session.addChannel();auto base=Clock::now();double cp=cpu();Protocol p(sid,ch);double base_s=elapsed(base),base_cpu=cpu()-cp;uint64_t base_bytes=ch.getTotalDataSent();
 int fd=accept(listener,nullptr,nullptr);close(listener);setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof yes);tx(fd,"R",1);std::cout<<"{\"base_ot_seconds\":"<<base_s<<",\"cpu_seconds\":"<<base_cpu<<",\"sent_bytes\":"<<base_bytes<<"}"<<std::endl;
 std::vector<Triple> pool;CountOT count_ot;uint32_t prepared_gates=0;bool ready=false;
 while(true){char mode;rx(fd,&mode,1);if(mode=='Q')break;
  if(mode=='P'){
   if(ready)throw std::runtime_error("unused preprocessing");uint32_t ng;rx(fd,&ng,4);prepared_gates=ntohl(ng);auto t=Clock::now();cp=cpu();auto bytes=ch.getTotalDataSent();
   for(size_t i=0;i<prepared_gates;++i){pool.push_back(fresh(p,n));pool.push_back(fresh(p,3*n));}double triple_s=elapsed(t);sync_peer(ch,sid);auto triple_bytes=ch.getTotalDataSent()-bytes;
   t=Clock::now();bytes=ch.getTotalDataSent();auto cot_recv_before=ch.getTotalDataRecv();count_ot.prepare(p,n);sync_peer(ch,sid);double cot_s=elapsed(t);auto cot_bytes=ch.getTotalDataSent()-bytes;auto cot_recv_bytes=ch.getTotalDataRecv()-cot_recv_before;ready=true;tx(fd,"P",1);
   std::cout<<std::setprecision(12)<<"{\"triple_seconds\":"<<triple_s<<",\"triple_sent_bytes\":"<<triple_bytes<<",\"count_random_ot_seconds\":"<<cot_s<<",\"count_random_ot_sent_bytes\":"<<cot_bytes<<",\"count_random_ot_received_bytes\":"<<cot_recv_bytes<<",\"cpu_seconds\":"<<cpu()-cp<<",\"fresh_boolean_triples\":"<<4*n*prepared_gates<<",\"fresh_count_random_ots\":"<<n<<"}"<<std::endl;continue;
  }
  if((mode!='T'&&mode!='V')||!ready)throw std::runtime_error("no fresh materials");ready=false;auto begin=Clock::now();cp=cpu();uint32_t length;rx(fd,&length,4);length=ntohl(length);if(length>10000000)throw std::runtime_error("length");std::string blob(length,'\0');rx(fd,blob.data(),length);std::istringstream in(blob);auto atoms=get<uint32_t>(in),ng=get<uint32_t>(in);if(ng!=prepared_gates)throw std::runtime_error("preprocess template");std::vector<Bytes> vectors;double dcf_s=0,dpf_s=0;
  for(size_t j=0;j<atoms;++j){auto col=get<uint32_t>(in);Key a=load(in),b=load(in);auto constant=get<uint8_t>(in);auto t=Clock::now();auto x=evaluate_atom(a,rows,col,sid);dcf_s+=elapsed(t);t=Clock::now();auto y=evaluate_atom(b,rows,col,sid);if(b.op)dcf_s+=elapsed(t);else dpf_s+=elapsed(t);for(size_t i=0;i<n;++i)x[i]^=y[i]^constant;vectors.push_back(std::move(x));}
  auto boolean_start=Clock::now();auto bytes=ch.getTotalDataSent();size_t used=0;
  for(size_t j=0;j<ng;++j){auto ai=get<uint32_t>(in),bi=get<uint32_t>(in);std::array<uint8_t,4> c;for(auto& v:c)v=get<uint8_t>(in);auto& x=vectors.at(ai);auto& y=vectors.at(bi);auto t=multiply(p,x,y,std::move(pool.at(used++)));Bytes left(3*n),right(3*n);
   for(size_t i=0;i<n;++i){left[i]=c[1];left[n+i]=c[2];left[2*n+i]=c[3];right[i]=x[i];right[n+i]=y[i];right[2*n+i]=t[i];}auto products=multiply(p,left,right,std::move(pool.at(used++)));Bytes out(n);for(size_t i=0;i<n;++i)out[i]=c[0]^products[i]^products[n+i]^products[2*n+i];vectors.push_back(std::move(out));}
  pool.clear();double boolean_s=elapsed(boolean_start);auto boolean_bytes=ch.getTotalDataSent()-bytes;auto& z=vectors.back();auto t=Clock::now();bytes=ch.getTotalDataSent();uint64_t m=count_ot.count(p,z);double count_s=elapsed(t);auto count_bytes=ch.getTotalDataSent()-bytes;
  double online_s=elapsed(begin),cpu_s=cpu()-cp;uint64_t net_m=htobe64(m);tx(fd,&net_m,8);if(mode=='V')tx(fd,z.data(),z.size());
  std::cout<<std::setprecision(12)<<"{\"dcf_seconds\":"<<dcf_s<<",\"dpf_seconds\":"<<dpf_s<<",\"boolean_seconds\":"<<boolean_s<<",\"boolean_sent_bytes\":"<<boolean_bytes<<",\"count_seconds\":"<<count_s<<",\"count_sent_bytes\":"<<count_bytes<<",\"online_server_seconds\":"<<online_s<<",\"cpu_seconds\":"<<cpu_s<<",\"m\":"<<m<<",\"query_bytes\":"<<length+5<<",\"boolean_rounds\":"<<2*ng<<",\"count_dependency_rounds\":3}"<<std::endl;
 }
 close(fd);ch.close();session.stop();io.stop();return 0;
 }catch(std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
