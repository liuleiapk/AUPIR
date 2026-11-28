// Default IPBM retrieval + unchanged descriptor selection and Batch PIR bridge.
#include "retrieval.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
void receive_all(int fd,void* dst,size_t n){auto p=(char*)dst;while(n){auto k=::recv(fd,p,n,0);if(k<=0)throw std::runtime_error("client receive");p+=k;n-=k;}}
void send_all(int fd,const void* src,size_t n){auto p=(const char*)src;while(n){auto k=::send(fd,p,n,MSG_NOSIGNAL);if(k<=0)throw std::runtime_error("client send");p+=k;n-=k;}}
int main(int argc,char**argv){try{
 if(argc<2)throw std::runtime_error("command");std::string cmd=argv[1];
 if(cmd=="keygen"){
  if(argc!=4)throw std::runtime_error("keygen spec prefix");std::ifstream spec(argv[2]);
  std::ofstream f0(std::string(argv[3])+".0",std::ios::binary),f1(std::string(argv[3])+".1",std::ios::binary);
  std::cout<<generate_query(spec,f0,f1).json()<<std::endl;return 0;
 }
 if((cmd!="server"&&cmd!="retrieval-server")||argc!=6)throw std::runtime_error("server sid dir peer clientport");
 int sid=std::stoi(argv[2]);if(sid!=0&&sid!=1)throw std::runtime_error("sid");std::string dir=argv[3];
 auto load_start=Clock::now();std::ifstream cfg(dir+"/template");auto shape=PublicTemplate::read(cfg);auto n=shape.n,width=shape.width;
 std::ifstream table(dir+"/table");std::vector<std::vector<uint64_t>> rows(n,std::vector<uint64_t>(shape.fields));
 for(auto& row:rows)for(auto& x:row)table>>x;if(!table)throw std::runtime_error("table");double load_s=elapsed(load_start);
 int listener=::socket(AF_INET,SOCK_STREAM,0),yes=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
 sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(std::getenv("IPBM_LISTEN_ANY")?INADDR_ANY:INADDR_LOOPBACK);addr.sin_port=htons(std::stoi(argv[5]));
 if(bind(listener,(sockaddr*)&addr,sizeof addr)||listen(listener,1))throw std::runtime_error("listen");
 auto session_start=Clock::now();IOService io(1);Session session(io,argv[4],sid?SessionMode::Client:SessionMode::Server,"ipbm-default-v2");auto channel=session.addChannel();
 auto base_start=Clock::now();auto cp=cpu();Protocol p(sid,channel);sync_peer(channel,sid);
 Metrics base{{"base_ot_seconds",elapsed(base_start)},{"session_server_seconds",elapsed(session_start)},{"cpu_seconds",cpu()-cp},
  {"sent_bytes",double(channel.getTotalDataSent())},{"attribute_load_seconds",load_s}};
 int fd=accept(listener,nullptr,nullptr);if(fd<0)throw std::runtime_error("accept");close(listener);setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof yes);
 send_all(fd,"R",1);std::cout<<base.json()<<std::endl;RetrievalSession retrieval(p,shape);Bytes z;uint64_t m=0;
 while(true){char mode;receive_all(fd,&mode,1);if(mode=='Q'){if(cmd=="server")throw std::runtime_error("missing query");break;}
  if(mode=='P'){auto metrics=retrieval.prepare();send_all(fd,"P",1);std::cout<<metrics.json()<<std::endl;continue;}
  bool validate=false;
#ifdef IPBM_TEST_EXPORT
  validate=mode=='V';
#endif
  if(mode!='T'&&!validate)throw std::runtime_error("production retrieval mode");
  auto start=Clock::now();uint32_t length;receive_all(fd,&length,4);length=ntohl(length);
  size_t expected=12+9*shape.gates.size();for(auto& a:shape.atoms)expected+=9+48*(a.second+1);
  if(length!=expected)throw std::runtime_error("fixed query frame size");std::string blob(length,'\0');receive_all(fd,blob.data(),length);
  auto result=retrieval.evaluate(blob,rows);z=std::move(result.z);m=result.m;uint64_t wire_m=htobe64(m);send_all(fd,&wire_m,8);
  result.metrics["receive_evaluate_deliver_seconds"]=elapsed(start);
  // Optional, server-private correctness audit. Never sent to C and disabled
  // in normal execution. The experiment auditor reads it after the endpoint.
  if(std::getenv("IPBM_PRIVATE_AUDIT")){std::ofstream audit(dir+"/audit-z",std::ios::binary);audit.write((char*)z.data(),z.size());}
#ifdef IPBM_TEST_EXPORT
  if(validate)send_all(fd,z.data(),z.size());
#endif
  std::cout<<result.metrics.json()<<std::endl;
  if(cmd=="server")break;
 }
 close(fd);
 if(cmd=="retrieval-server"){channel.close();session.stop();io.stop();return 0;}
 // C receives m before starting the existing association/description stage.
 std::string trigger;std::getline(std::cin,trigger);if(trigger!="DESCRIBE")throw std::runtime_error("description trigger");
 auto description_start=Clock::now();auto description_cp=cpu();auto description_sent=channel.getTotalDataSent();
 rows.clear();Bytes d(n*width);std::ifstream desc(dir+"/descriptions",std::ios::binary);desc.read((char*)d.data(),d.size());if(!desc)throw std::runtime_error("description");
 auto u=p.cross(0,z,d,width),v=p.cross(1,z,d,width);for(size_t i=0;i<n;++i)for(size_t j=0;j<width;++j)d[i*width+j]=(z[i]?d[i*width+j]:0)^u[i*width+j]^v[i*width+j];
 // Shared fresh seed is server-only, used for permutation and PIR masks.
 block seed;if(!sid){seed=p.rng.get<block>();channel.send(&seed,1);}else channel.recv(&seed,1);PRNG shuffle(seed);
 std::vector<size_t> perm(n);std::iota(perm.begin(),perm.end(),0);for(size_t i=n;i>1;--i){uint64_t r,limit=uint64_t(-1)-uint64_t(-1)%i;do{r=shuffle.get<uint64_t>();}while(r>=limit);std::swap(perm[i-1],perm[r%i]);}
 std::ofstream out(dir+"/selected",std::ios::binary);for(auto i:perm)out.write((char*)d.data()+i*width,width);out.close();
 double description_seconds=elapsed(description_start),description_cpu=cpu()-description_cp;auto description_bytes=channel.getTotalDataSent()-description_sent;
 // Seed remains in this process; consume one fixed key request, invoke existing
 // backend in a child process, mask all response bytes before exposing to C.
 std::cout<<"READY"<<std::endl;std::string ack;std::getline(std::cin,ack);if(ack!="PIR")throw std::runtime_error("PIR trigger");
 auto pir_start=Clock::now();auto pir_cp=cpu();
 std::ifstream command(dir+"/backend-command");std::string line;std::getline(command,line);if(std::system(line.c_str()))throw std::runtime_error("backend failure");
 std::ifstream raw(dir+"/raw-response",std::ios::binary);std::ofstream masked(dir+"/response",std::ios::binary);char buf[65536];PRNG mask(seed ^ toBlock(0x5049524d41534bULL,0x7631));uint64_t bytes=0;
 while(raw){raw.read(buf,sizeof buf);auto k=raw.gcount();Bytes pad(k);mask.get(pad.data(),k);for(size_t i=0;i<(size_t)k;++i)buf[i]^=pad[i];masked.write(buf,k);bytes+=k;}masked.close();
 std::cout<<"{\"peer_sent_bytes\":"<<channel.getTotalDataSent()<<",\"peer_received_bytes\":"<<channel.getTotalDataRecv()<<",\"chosen_ot_sent_messages\":"<<p.sent<<",\"chosen_ot_received_messages\":"<<p.received<<",\"description_count\":"<<n<<",\"description_bytes\":"<<n*width<<",\"pir_response_bytes\":"<<bytes<<",\"description_seconds\":"<<description_seconds<<",\"description_cpu_seconds\":"<<description_cpu<<",\"description_peer_sent_bytes\":"<<description_bytes<<",\"pir_and_mask_seconds\":"<<elapsed(pir_start)<<",\"pir_and_mask_parent_cpu_seconds\":"<<cpu()-pir_cp<<"}"<<std::endl;
 channel.close();session.stop();io.stop();return 0;
 }catch(std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}}
