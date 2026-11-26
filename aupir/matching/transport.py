"""Local two-process transport used by BOTH the default pipeline and benchmark."""
from __future__ import annotations
import hashlib,json,socket,struct,subprocess,time
from pathlib import Path
from .compiler import compile_query,private_spec

HERE=Path(__file__).resolve().parent
ENGINE=HERE/'engine'


def receive(sock,n):
    result=bytearray()
    while len(result)<n:
        part=sock.recv(n-len(result))
        if not part:
            raise RuntimeError('retrieval server closed connection')
        result.extend(part)
    return bytes(result)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def prepare_query(expr,fields,output,*,engine=ENGINE,validation=False):
    start=time.perf_counter()
    atoms,gates=compile_query(expr,fields)
    compile_seconds=time.perf_counter()-start
    spec=output/'private-query'
    spec.write_text(private_spec(atoms,gates))
    tick=time.perf_counter()
    keygen=subprocess.run([str(engine),'keygen',str(spec),str(output/'fss')],capture_output=True,text=True,check=True)
    process_seconds=time.perf_counter()-tick
    metrics=json.loads(keygen.stdout)
    blobs=[(output/f'fss.{sid}').read_bytes() for sid in (0,1)]
    frames=[(b'V' if validation else b'T')+struct.pack('!I',len(blob))+blob for blob in blobs]
    preparation_seconds=time.perf_counter()-start
    return dict(atoms=atoms,gates=gates,frames=frames,
                preparation_seconds=preparation_seconds,compile_seconds=compile_seconds,
                keygen_process_seconds=process_seconds,keygen=metrics,
                hashes=[hashlib.sha256(blob).hexdigest() for blob in blobs])


class ServerPair:
    def __init__(self,dirs,*,mode='retrieval-server',engine=ENGINE,
                 server_hosts=None,process_prefixes=None,server_env=None):
        self.mode=mode;self.dirs=dirs;self.servers=[];self.sockets=[];self.errors=[]
        start=time.perf_counter()
        ports=set()
        while len(ports)<3:ports.add(free_port())
        peer,*clients=ports
        hosts=server_hosts or ['127.0.0.1']*2
        prefixes=process_prefixes or [[],[]]
        try:
            for sid in (0,1):
                error=(dirs[sid]/'retrieval.stderr').open('w');self.errors.append(error)
                self.servers.append(subprocess.Popen([*prefixes[sid],str(engine),mode,str(sid),str(dirs[sid]),f'{hosts[0]}:{peer}',str(clients[sid])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=error,text=True,env=server_env))
            for sid,port in enumerate(clients):
                deadline=time.monotonic()+90
                while True:
                    try:sock=socket.create_connection((hosts[sid],port),timeout=1);break
                    except OSError:
                        if self.servers[sid].poll() is not None:raise RuntimeError((dirs[sid]/'retrieval.stderr').read_text())
                        if time.monotonic()>deadline:raise TimeoutError('retrieval startup')
                        time.sleep(.01)
                sock.settimeout(90);sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);self.sockets.append(sock)
                if receive(sock,1)!=b'R':raise RuntimeError('retrieval session ready')
            self.session_seconds=time.perf_counter()-start
            self.base_metrics=self.metrics()
        except BaseException:
            self.close();raise

    def metrics(self):
        result=[]
        for sid,p in enumerate(self.servers):
            line=p.stdout.readline()
            if not line:raise RuntimeError((self.dirs[sid]/'retrieval.stderr').read_text())
            result.append(json.loads(line))
        return result

    def prepare(self):
        start=time.perf_counter()
        for sock in self.sockets:sock.sendall(b'P')
        for sock in self.sockets:
            if receive(sock,1)!=b'P':raise RuntimeError('preprocessing ready')
        seconds=time.perf_counter()-start
        return seconds,self.metrics()

    def run(self,frames,*,validation_n=None):
        start=time.perf_counter()
        for sock,frame in zip(self.sockets,frames):sock.sendall(frame)
        counts=[struct.unpack('!Q',receive(sock,8))[0] for sock in self.sockets]
        self.last_delivery_time=time.perf_counter()
        seconds=self.last_delivery_time-start
        if counts[0]!=counts[1]:raise RuntimeError('server count mismatch')
        vector=None
        if validation_n is not None:
            shares=[receive(sock,validation_n) for sock in self.sockets]
            vector=bytes(x^y for x,y in zip(*shares))
        metrics=self.metrics()
        return seconds,counts[0],metrics,vector

    def close(self):
        for sock in self.sockets:
            try:
                if self.mode=='retrieval-server':sock.sendall(b'Q')
                sock.close()
            except OSError:pass
        for p in self.servers:
            if p.poll() is None:
                if self.mode=='server':p.kill()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            if p.stdin:p.stdin.close()
            if p.stdout:p.stdout.close()
        for error in self.errors:error.close()
