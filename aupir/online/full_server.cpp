// AUPIR Algorithm 2. IPBM is imported unchanged; party-local backend pipe
// and files never cross the client/server boundary. All party messages use TCP.
#include "../matching/retrieval.h"
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstdio>
#include <sys/random.h>
void rx(int fd,void* dst,size_t n){auto p=(char*)dst;while(n){auto k=recv(fd,p,n,0);if(k<=0)throw std::runtime_error("TCP receive");p+=k;n-=k;}}
void tx(int fd,const void* src,size_t n){auto p=(const char*)src;while(n){auto k=send(fd,p,n,MSG_NOSIGNAL);if(k<=0)throw std::runtime_error("TCP send");p+=k;n-=k;}}
uint64_t number(int fd){uint64_t x;rx(fd,&x,8);return be64toh(x);}
void number(int fd,uint64_t x){x=htobe64(x);tx(fd,&x,8);}
void uniform_bytes(Bytes& bytes){size_t at=0;while(at<bytes.size()){auto k=getrandom(bytes.data()+at,bytes.size()-at,0);if(k<0&&errno==EINTR)continue;if(k<=0)throw std::runtime_error("OCC uniform randomness");at+=k;}}
Bytes load(const std::string& path){std::ifstream f(path,std::ios::binary);if(!f)throw std::runtime_error("private input "+path);return Bytes(std::istreambuf_iterator<char>(f),{});}
void save(const std::string& path,const Bytes& b){std::ofstream f(path,std::ios::binary);f.write((char*)b.data(),b.size());if(!f)throw std::runtime_error("private write");}
std::string digest(const void* b,size_t n){unsigned char hash[32];SHA256((const unsigned char*)b,n,hash);std::ostringstream s;for(auto x:hash)s<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(x);return s.str();}

// Chosen-message OT via preprocessed random OTs. Receiver correction and two
// masked messages per 128-bit chunk are sent online. Every pad is consumed once.
struct DescriptorOT {
 std::vector<std::array<block,2>> pads;std::vector<block> selected;BitVector choices;bool ready=false;
 void prepare(Protocol& p,size_t n){if(ready)throw std::runtime_error("descriptor OT reuse");if(!p.sid){pads.resize(n);p.sender.send(pads,p.rng,p.ch);}else{choices.resize(n);choices.randomize(p.rng);selected.resize(n);p.receiver.receive(choices,selected,p.rng,p.ch);}ready=true;}
 Bytes select(Protocol& p,const Bytes& g,const Bytes& tagged){
  constexpr size_t W=144,K=9;size_t n=g.size(),count=n*K;
  if(!ready)throw std::runtime_error("descriptor OT unprepared");ready=false;
  Bytes delta(count),wire(count*32),out(n*W);
  if(p.sid){for(size_t i=0;i<count;++i)delta[i]=choices[i]^g[i/K];p.send(delta);p.recv(wire);
   for(size_t i=0;i<count;++i){uint8_t pad[16];memcpy(pad,&selected[i],16);for(size_t j=0;j<16;++j)out[i*16+j]=pad[j]^wire[i*32+16*g[i/K]+j];}}
  else{p.recv(delta);p.rng.get(out.data(),out.size());
   for(size_t i=0;i<count;++i)for(size_t b=0;b<2;++b){uint8_t pad[16];memcpy(pad,&pads[i][b^delta[i]],16);for(size_t j=0;j<16;++j)wire[i*32+16*b+j]=pad[j]^out[i*16+j]^((g[i/K]^b)?tagged[i*16+j]:0);}
   p.send(wire);}
  pads.clear();selected.clear();choices.resize(0);return out;
 }
};
size_t eta_for(size_t m){size_t k=128,x=1;while(x<m){x*=2;++k;}return k;}
// Public independently framed hashes of permuted slots. GF(2) addition is
// bytewise XOR (including repeated hash occurrences), not integer addition.
Bytes bfs_encode(const Bytes& v,const std::vector<size_t>& perm,uint64_t id,size_t m){
 size_t eta=eta_for(m),ell=2*(eta*m-1);Bytes out(ell*144);
 for(size_t j=0;j<perm.size();++j)for(size_t h=0;h<eta;++h){
  uint64_t words[5]={htobe64(0x4246532d50324f31ULL),htobe64(id),htobe64(j),htobe64(h),0};unsigned char hash[32];uint64_t x,counter=0,threshold=(uint64_t(0)-ell)%ell;
  do{words[4]=htobe64(counter++);SHA256((unsigned char*)words,sizeof words,hash);x=0;for(size_t k=0;k<8;++k)x=(x<<8)|hash[k];}while(x<threshold);size_t cell=x%ell;
  for(size_t k=0;k<144;++k)out[cell*144+k]^=v[perm[j]*144+k];
 }return out;
}
struct Backend {
 pid_t pid=-1;FILE* in=nullptr;FILE* out=nullptr;
 Backend(const std::vector<std::string>& args){int a[2],b[2];if(pipe(a)||pipe(b))throw std::runtime_error("backend pipe");pid=fork();if(pid<0)throw std::runtime_error("fork");if(!pid){dup2(a[0],0);dup2(b[1],1);for(int fd:{a[0],a[1],b[0],b[1]})close(fd);std::vector<char*> v;for(auto& s:args)v.push_back(const_cast<char*>(s.c_str()));v.push_back(nullptr);execv(v[0],v.data());_exit(127);}close(a[0]);close(b[1]);in=fdopen(a[1],"w");out=fdopen(b[0],"r");}
 std::string line(){char* p=nullptr;size_t n=0;auto k=getline(&p,&n,out);if(k<0){free(p);throw std::runtime_error("backend ended");}std::string s(p,k);free(p);return s;}
 std::string run(const std::string& request){fprintf(in,"%s\n",request.c_str());fflush(in);return line();}
 ~Backend(){if(in){fprintf(in,"QUIT\n");fclose(in);}if(out)fclose(out);if(pid>0)waitpid(pid,nullptr,0);}
};
int main(int argc,char** argv){try{
 if(argc!=6)throw std::runtime_error("full-server sid private-dir peer client-port");int sid=std::stoi(argv[2]);if(sid<0||sid>1)throw std::runtime_error("sid");std::string dir=argv[3];
 auto init=Clock::now();std::ifstream cfg(dir+"/template");auto shape=PublicTemplate::read(cfg);auto n=shape.n;
 std::ifstream table(dir+"/table");std::vector<std::vector<uint64_t>> rows(n,std::vector<uint64_t>(shape.fields));for(auto& row:rows)for(auto& x:row)table>>x;if(!table)throw std::runtime_error("table");
 auto tagged=load(dir+"/tagged-descriptors");if(tagged.size()!=n*144)throw std::runtime_error("tagged descriptor shape");
 std::ifstream config(dir+"/full-config");std::string backend;uint64_t blocks,B,Q,version,pbc,r,width,ls,threads;config>>backend>>blocks>>B>>Q>>version>>pbc>>r>>width>>ls>>threads;if(!config)throw std::runtime_error("full-config");uint64_t H=(3*Q+1)/2;
 if(r!=Q+40||width!=r||ls!=0||r>=H)throw std::runtime_error("OCC finite parameter profile");
 Backend worker({backend,"serve","indirected_file",std::to_string(blocks),std::to_string(B),std::to_string(Q),std::to_string(B),std::to_string(version),std::to_string(pbc),std::to_string(sid),"paper_faithful_optimized",std::to_string(threads),"scalar","row_major","fixed_explicit",dir+"/database.img"});auto setup=worker.line();
 int listener=socket(AF_INET,SOCK_STREAM,0),yes=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(std::stoi(argv[5]));if(bind(listener,(sockaddr*)&addr,sizeof addr)||listen(listener,1))throw std::runtime_error("listen");
 IOService io(1);Session session(io,argv[4],sid?SessionMode::Client:SessionMode::Server,"aupir-online-v1");auto ch=session.addChannel();auto base=Clock::now();auto basecp=cpu();Protocol p(sid,ch);sync_peer(ch,sid);
 std::string hello=session.getName()+"`"+std::to_string(session.getSessionID())+"`_autoName_0`_autoName_0";
 Metrics bm{{"base_ot_seconds",elapsed(base)},{"base_ot_cpu_seconds",cpu()-basecp},{"peer_sent_bytes",double(ch.getTotalDataSent())},{"negotiation_sent_bytes",double(sid?4+hello.size():1)},{"initialization_seconds",elapsed(init)}};
 int fd=accept(listener,nullptr,nullptr);close(listener);if(fd<0)throw std::runtime_error("accept");setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof yes);tx(fd,"R",1);std::cout<<"{\"session\":"<<bm.json()<<",\"backend\":"<<setup.substr(0,setup.find_last_not_of("\r\n")+1)<<"}"<<std::endl;
 RetrievalSession retrieval(p,shape);DescriptorOT ot;bool ready=false;uint64_t epoch=0;std::vector<size_t> perm;std::string material;Bytes matrix;
 while(true){char command;rx(fd,&command,1);if(command=='Q')break;uint64_t id=number(fd);
  if(command=='P'){
   if(ready||id!=epoch+1)throw std::runtime_error("material epoch/reuse");auto start=Clock::now();auto cp=cpu();auto bytes=ch.getTotalDataSent();auto rm=retrieval.prepare();ot.prepare(p,n*9);
   // Two independent joint CSPRNG seeds, with independent contributions from
   // both parties. Permutation randomness and response-mask randomness are
   // independent; no related-key assumption or seed reuse between primitives.
   std::array<block,2> local,remote,seed;for(auto& b:local)b=p.rng.get<block>();
   if(!sid){ch.send(local.data(),2);ch.recv(remote.data(),2);}else{ch.recv(remote.data(),2);ch.send(local.data(),2);}for(size_t j=0;j<2;++j)seed[j]=local[j]^remote[j];material=digest(seed.data(),32);
   PRNG shuffle(seed[0]);perm.resize(n);std::iota(perm.begin(),perm.end(),0);for(size_t i=n;i>1;--i){uint64_t x,limit=uint64_t(-1)-uint64_t(-1)%i;do{x=shuffle.get<uint64_t>();}while(x>=limit);std::swap(perm[i-1],perm[x%i]);}
   PRNG mask(seed[1]);Bytes mu(H*B);mask.get(mu.data(),mu.size());save(dir+"/one-use-mask",mu);
   // LS Setup randomness: explicit uniform full-band columns, fresh each
   // call. R is shared by the servers offline, and remains unknown to C until
   // C has submitted its complete fixed-shape DPF query to both servers.
   size_t stride=(r+7)/8;matrix.resize(H*stride);
   if(!sid){uniform_bytes(matrix);if(r%8)for(size_t j=0;j<H;++j)matrix[j*stride+stride-1]&=(1u<<(r%8))-1;ch.send(matrix.data(),matrix.size());}else ch.recv(matrix.data(),matrix.size());
   save(dir+"/one-use-occ-matrix",matrix);sync_peer(ch,sid);epoch=id;ready=true;
   Metrics m{{"seconds",elapsed(start)},{"cpu_seconds",cpu()-cp},{"peer_sent_bytes",double(ch.getTotalDataSent()-bytes)},{"descriptor_random_ots",double(n*9)},{"mask_bytes",double(H*B)},{"occ_matrix_bytes",double(matrix.size())},{"epoch",double(id)}};
   tx(fd,"P",1);number(fd,id);std::cout<<"{\"preprocessing\":"<<m.json()<<",\"ipbm\":"<<rm.json()<<",\"material_commitment\":\""<<material<<"\"}"<<std::endl;continue;
  }
  if(command!='T'||!ready||id!=epoch)throw std::runtime_error("query epoch/unprepared/replay");ready=false;auto start=Clock::now();auto cp=cpu();auto sent=ch.getTotalDataSent();
  auto len=number(fd);size_t expected=12+9*shape.gates.size();for(auto& a:shape.atoms)expected+=9+48*(a.second+1);if(len!=expected)throw std::runtime_error("query shape");std::string blob(len,'\0');rx(fd,blob.data(),len);auto result=retrieval.evaluate(blob,rows);number(fd,result.m);
  if(!result.m){ot.ready=false;ot.pads.clear();ot.selected.clear();ot.choices.resize(0);matrix.clear();number(fd,0);unlink((dir+"/one-use-mask").c_str());unlink((dir+"/one-use-occ-matrix").c_str());std::cout<<"{\"epoch\":"<<id<<",\"empty\":true,\"ipbm\":"<<result.metrics.json()<<",\"peer_sent_bytes\":"<<ch.getTotalDataSent()-sent<<",\"cpu_seconds\":"<<cpu()-cp<<",\"seconds\":"<<elapsed(start)<<"}"<<std::endl;continue;}
  auto descstart=Clock::now();auto v=ot.select(p,result.z,tagged);double select_seconds=elapsed(descstart);auto bfsstart=Clock::now();auto encoded=bfs_encode(v,perm,id,result.m);double bfs_seconds=elapsed(bfsstart);number(fd,encoded.size());tx(fd,encoded.data(),encoded.size());double descs=elapsed(descstart);
  // Receive only this server's fixed-shape DPF keys. C cannot read private
  // descriptors, database, matching shares, raw responses, or response masks.
  uint64_t keylen=number(fd);uint64_t ell=0;while((1ULL<<ell)<blocks+Q+1)++ell;uint64_t keysize=96+H*(4+33+18*(ell>7?ell-7:0));if(keylen!=keysize)throw std::runtime_error("PIR key shape");Bytes key(keylen);rx(fd,key.data(),key.size());
  uint64_t kh[9];memcpy(kh,key.data(),72);uint32_t flags[6];memcpy(flags,key.data()+72,24);if(kh[1]!=blocks||kh[2]!=B||kh[3]!=Q||kh[4]!=H||kh[5]!=pbc||kh[6]!=ls||kh[7]!=version||flags[1]!=1||flags[2]!=r||flags[3]!=width||flags[4]!=40||flags[5]!=4)throw std::runtime_error("PIR public parameters");save(dir+"/one-use.keys",key);
  number(fd,matrix.size());tx(fd,matrix.data(),matrix.size());std::string matrix_hash=digest(matrix.data(),matrix.size());
  auto backend_metrics=worker.run(dir+"/one-use.keys "+dir+"/compressed "+dir+"/one-use-mask "+dir+"/one-use-occ-matrix");auto response=load(dir+"/compressed");if(response.size()!=r*B)throw std::runtime_error("compressed response shape");number(fd,response.size());tx(fd,response.data(),response.size());unlink((dir+"/one-use-mask").c_str());unlink((dir+"/one-use.keys").c_str());unlink((dir+"/compressed").c_str());unlink((dir+"/one-use-occ-matrix").c_str());matrix.clear();
  std::cout<<"{\"epoch\":"<<id<<",\"ipbm\":"<<result.metrics.json()<<",\"backend\":"<<backend_metrics.substr(0,backend_metrics.find_last_not_of("\r\n")+1)<<",\"occ_matrix_sha256\":\""<<matrix_hash<<"\",\"bfs_encode_calls\":1,\"bfs_response_bytes\":"<<encoded.size()<<",\"description_ot_seconds\":"<<select_seconds<<",\"bfs_encode_seconds\":"<<bfs_seconds<<",\"description_seconds\":"<<descs<<",\"peer_sent_bytes\":"<<ch.getTotalDataSent()-sent<<",\"parent_cpu_seconds\":"<<cpu()-cp<<",\"seconds\":"<<elapsed(start)<<"}"<<std::endl;
 }
 close(fd);ch.close();session.stop();io.stop();return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
