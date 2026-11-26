#!/usr/bin/env python3
"""Same database/template, paired real-crypto loopback process experiment.

Validation alone exports vectors; timed runs return only m. No DO online,
descriptor handling, object capacities, or Batch PIR runs in this harness.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,random,socket,statistics,struct,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def receive(s,n):
    b=bytearray()
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:raise RuntimeError('worker closed')
        b.extend(c)
    return bytes(b)

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Servers:
    def __init__(self,path,rows):
        self.path=path;path.mkdir();self.n=len(rows);self.ps=[];self.ss=[]
        table=path/'table';table.write_text(f'{len(rows)} {len(rows[0])}\n'+'\n'.join(' '.join(map(str,r)) for r in rows))
        peer=port();ports=[port(),port()]
        for sid in (0,1):
            self.ps.append(subprocess.Popen([str(HERE/'worker'),'server',str(sid),str(table),f'127.0.0.1:{peer}',str(ports[sid])],stdout=subprocess.PIPE,stderr=(path/f's{sid}.stderr').open('w'),text=True))
        for sid,p in enumerate(ports):
            deadline=time.monotonic()+90
            while True:
                try:s=socket.create_connection(('127.0.0.1',p),timeout=1);break
                except OSError:
                    if self.ps[sid].poll() is not None:raise RuntimeError((path/f's{sid}.stderr').read_text())
                    if time.monotonic()>deadline:raise TimeoutError('worker startup')
                    time.sleep(.02)
            s.settimeout(90);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);self.ss.append(s)
            assert receive(s,1)==b'R'
        self.base=[json.loads(p.stdout.readline()) for p in self.ps]
    def query(self,route,atoms,gates,index,validate=False):
        # Preprocessing depends only on public gate count and N. Fresh per run.
        t=time.perf_counter()
        for s in self.ss:s.sendall(b'P'+struct.pack('!I',len(gates)))
        for s in self.ss:assert receive(s,1)==b'P'
        pre_s=time.perf_counter()-t;pre=[json.loads(p.stdout.readline()) for p in self.ps]
        prep_start=time.perf_counter()
        spec=self.path/'private-spec'
        spec.write_text(f'{len(atoms)} {len(gates)}\n'+'\n'.join(f'{c} {b} {op} {v}' for c,b,op,v in atoms)+'\n'+'\n'.join(f'{op} {a} {b}' for op,a,b in gates)+'\n')
        prefix=self.path/'private-keys';t=time.perf_counter()
        r=subprocess.run([str(HERE/'worker'),'keygen',route,str(spec),str(prefix)],capture_output=True,text=True,check=True)
        prep_wall=time.perf_counter()-t;gen=json.loads(r.stdout)
        blobs=[Path(str(prefix)+f'.{sid}').read_bytes() for sid in (0,1)]
        frames=[(b'V' if validate else b'T')+struct.pack('!I',len(b))+b for b in blobs]
        preparation=time.perf_counter()-prep_start
        t=time.perf_counter()
        for s,b in zip(self.ss,frames):s.sendall(b)
        counts=[struct.unpack('!Q',receive(s,8))[0] for s in self.ss]
        online=time.perf_counter()-t
        shares=[receive(s,self.n) for s in self.ss] if validate else None
        vector=bytes(a^b for a,b in zip(*shares)) if validate else None
        metrics=[json.loads(p.stdout.readline()) for p in self.ps]
        assert counts[0]==counts[1] and all(m['m']==counts[0] for m in metrics)
        return dict(route=route,index=index,validation=validate,online_seconds=online,
                    keygen_process_seconds=prep_wall,query_preparation_seconds=preparation,request_seconds=preparation+online,
                    algorithm_request_seconds=gen['keygen_seconds']+online,
                    preprocessing_seconds=pre_s,preprocessing=pre,keygen=gen,
                    query_bytes=[len(f) for f in frames],m=counts[0],server_metrics=metrics,
                    query_hashes=[hashlib.sha256(b).hexdigest() for b in blobs]),vector
    def close(self):
        for s in self.ss:
            try:s.sendall(b'Q');s.close()
            except OSError:pass
        for p in self.ps:
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait()
            if p.returncode:raise RuntimeError(f'worker failed: {self.path}')

def oracle(rows,atoms,gates):
    v=[]
    for col,bits,op,t in atoms:
        v.append([int({'GT':x>t,'GE':x>=t,'LT':x<t,'LE':x<=t,'EQ':x==t,'NE':x!=t}[op]) for x in (r[col] for r in rows)])
    for op,a,b in gates:
        v.append([int({'AND':x&y,'OR':x|y,'XOR':x^y,'NOT':1^x,'ID':x}[op]) for x,y in zip(v[a],v[b])])
    return bytes(v[-1])

def validation_cases():
    cases=[]
    # Whole small domains, including beta=0 in both fixed slots and 1-bit fields.
    for bits in (1,2,3,4,8):
        for t in range(1<<bits):
            for op in ('GT','GE','LT','LE','EQ','NE'):
                cases.append((f'b{bits}-{op}-{t}',[(0,bits,op,t)],[]))
    # Full 32-bit endpoints, and all open/closed double-ended intervals.
    for t in (0,1,34,35,36,100,2**32-2,2**32-1):
        for op in ('GT','GE','LT','LE','EQ','NE'):cases.append((f'u32-{op}-{t}',[(2,32,op,t)],[]))
    for lo,hi in ((0,0),(0,2**32-1),(35,35),(34,36),(2**32-1,2**32-1),(36,34)):
        for lop in ('GT','GE'):
            for hop in ('LT','LE'):cases.append((f'range-{lo}-{hi}-{lop}-{hop}',[(2,32,lop,lo),(2,32,hop,hi)],[('AND',0,1)]))
    for op in ('AND','OR','XOR','NOT','ID'):
        for x in (0,1):
            for y in (0,1):
                cases.append((f'gate-{op}-{x}-{y}',[(1,1,'GE' if x else 'LT',0),(1,1,'GE' if y else 'LT',0)],[(op,0,1)]))
    a=[(1,1,'EQ',1),(2,32,'GT',35),(2,32,'LT',1)]
    cases.append(('nested',a,[('AND',0,1),('NOT',2,2),('OR',3,4)]))
    return cases

def median(xs):return statistics.median(xs)
def summarize(samples):
    out={}
    for route in ('A','B'):
        ss=[s for s in samples if s['route']==route]
        def client(k):return median([s[k] for s in ss])*1000
        def critical(k):return median([max(m[k] for m in s['server_metrics']) for s in ss])*1000
        def pre(k):return median([max(m[k] for m in s['preprocessing']) for s in ss])*1000
        first=ss[0]
        out[route]=dict(online_ms=client('online_seconds'),online_min_ms=min(s['online_seconds'] for s in ss)*1000,
            online_max_ms=max(s['online_seconds'] for s in ss)*1000,keygen_process_ms=client('keygen_process_seconds'),query_preparation_ms=client('query_preparation_seconds'),
            keygen_ms=median([s['keygen']['keygen_seconds'] for s in ss])*1000,
            request_ms=client('request_seconds'),algorithm_request_ms=client('algorithm_request_seconds'),
            eval_ms=median([max(m['dcf_seconds']+m['dpf_seconds'] for m in s['server_metrics']) for s in ss])*1000,
            dcf_ms=critical('dcf_seconds'),dpf_ms=critical('dpf_seconds'),boolean_ms=critical('boolean_seconds'),count_ms=critical('count_seconds'),
            preprocessing_ms=client('preprocessing_seconds'),triple_ms=pre('triple_seconds'),count_random_ot_ms=pre('count_random_ot_seconds'),
            server_cpu_sum_ms=median([sum(m['cpu_seconds'] for m in s['server_metrics']) for s in ss])*1000,
            preprocessing_cpu_sum_ms=median([sum(m['cpu_seconds'] for m in s['preprocessing']) for s in ss])*1000,
            query_bytes=first['query_bytes'],pairs=first['keygen']['pairs'],
            boolean_peer_bytes=sum(m['boolean_sent_bytes'] for m in first['server_metrics']),
            count_peer_bytes=sum(m['count_sent_bytes'] for m in first['server_metrics']),
            triple_peer_bytes=sum(m['triple_sent_bytes'] for m in first['preprocessing']),
            count_random_ot_peer_bytes=sum(m['count_random_ot_sent_bytes'] for m in first['preprocessing']),
            boolean_rounds=first['server_metrics'][0]['boolean_rounds'],count_dependency_rounds=3)
    out['ranges_overlap']=not(out['A']['online_max_ms']<out['B']['online_min_ms'] or out['B']['online_max_ms']<out['A']['online_min_ms'])
    out['lower_median']=min(('A','B'),key=lambda r:out[r]['online_ms'])
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--n',default='10000,100000');ap.add_argument('--repeats',type=int,default=9);ap.add_argument('--warmups',type=int,default=2);ap.add_argument('--validate',action='store_true');ap.add_argument('--validation-only',action='store_true');a=ap.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);os.sched_setaffinity(0,{0,1,2,3})
    for name in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','YACL_NUM_THREADS'):os.environ[name]='1'
    config=dict(command=[sys.executable,*sys.argv],runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cpus=sorted(os.sched_getaffinity(0)),platform=platform.platform(),warmups=a.warmups,repeats=a.repeats,transport='LOCAL_TWO_PROCESSES_LOOPBACK_TCP_NO_TLS',threads_per_server=1,
                cpu_model=subprocess.check_output(['lscpu'],text=True),build=json.loads((HERE/'build_manifest.json').read_text()))
    (a.out/'config.json').write_text(json.dumps(config,indent=2));results=[];hashes=set()
    if a.validate or a.validation_only:
        # 256 rows cover every b<=8 domain; values reduced per active bit width.
        cases=validation_cases();reports=[]
        grouped={}
        for name,atoms,gates in cases:grouped.setdefault(atoms[0][1] if atoms[0][0]==0 else 32,[]).append((name,atoms,gates))
        for bits,cases in grouped.items():
            if bits==32:
                vals=[0,1,34,35,36,100,2**32-2,2**32-1]
                rows=[[i, i%2,x] for i,x in enumerate(vals)]
            else:rows=[[i, i%2,i] for i in range(1<<bits)]
            servers=Servers(a.out/f'validation-b{bits}',rows)
            try:
                for name,atoms,gates in cases:
                    expected=oracle(rows,atoms,gates)
                    for route in ('A','B'):
                        sample,z=servers.query(route,atoms,gates,name,validate=True)
                        assert z==expected,(name,route,'vector mismatch')
                        assert sample['m']==sum(expected),(name,route,'count mismatch')
                        assert not any(h in hashes for h in sample['query_hashes']);hashes.update(sample['query_hashes'])
                        reports.append(dict(case=name,route=route,n=len(rows),m=sum(expected),query_bytes=sample['query_bytes'],passed=True))
                print(json.dumps({'validation_bits':bits,'queries':len(cases)*2}),flush=True)
            finally:servers.close()
        (a.out/'validation.json').write_text(json.dumps(dict(passed=True,queries=len(reports),cases=reports),indent=2))
    if a.validation_only:return
    for n in map(int,a.n.split(',')):
        rng=random.Random(20261109);rows=[[rng.randrange(2),rng.randrange(101)] for _ in range(n)]
        rows[:8]=[[1,34],[1,35],[1,36],[0,36],[1,50],[0,0],[1,2**32-1],[0,2**32-2]]
        # Existing primary query, same public field widths. Also check same-width
        # numerical comparisons and a range + NOT/OR linear gate list.
        workloads=[('sex_eq_age_gt',[(0,1,'EQ',1),(1,32,'GT',35)],[('AND',0,1)]),
                   ('numeric_eq_gt',[(1,32,'EQ',35),(1,32,'GT',34)],[('OR',0,1)]),
                   ('range_not_or',[(1,32,'GE',35),(1,32,'LE',100),(0,1,'NE',0)],[('AND',0,1),('NOT',2,2),('OR',3,4)])]
        servers=Servers(a.out/f'n{n}',rows)
        try:
            for name,atoms,gates in workloads:
                expected=oracle(rows,atoms,gates);samples=[]
                for route in ('A','B'):
                    sample,z=servers.query(route,atoms,gates,'validation',True);assert z==expected and sample['m']==sum(expected)
                    for i in range(a.warmups):servers.query(route,atoms,gates,f'warmup{i}')
                order=random.Random(20261114+n)
                for i in range(a.repeats):
                    routes=['A','B'];order.shuffle(routes)
                    for route in routes:
                        s,_=servers.query(route,atoms,gates,i);assert s['m']==sum(expected)
                        assert not any(h in hashes for h in s['query_hashes']);hashes.update(s['query_hashes']);samples.append(s)
                summary=summarize(samples)
                results.append(dict(n=n,workload=name,atoms=atoms,gates=gates,m=sum(expected),data_sha256=hashlib.sha256(json.dumps(rows).encode()).hexdigest(),base_ot=servers.base,summary=summary,samples=samples))
                (a.out/'results.json').write_text(json.dumps(results,indent=2));print(json.dumps(dict(n=n,workload=name,summary=summary)),flush=True)
        finally:servers.close()
if __name__=='__main__':main()
