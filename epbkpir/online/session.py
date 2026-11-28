"""Client API and reusable local TCP parties for paper Algorithm 2.

Client reads public.json and its own output directory only. Server private
directories are passed to the launcher, never opened for query responses.
Unauthenticated loopback TCP is a local deployment fixture; external deployment
must supply the paper's authenticated confidential channels.
"""
from __future__ import annotations
import hashlib,json,math,os,resource,secrets,struct,subprocess,time
from pathlib import Path
from epbkpir.matching.compiler import compile_query,public_template
from epbkpir.matching.transport import ServerPair,prepare_query,receive
from epbkpir.layout import Locator,recover_object
from . import bfs
from .parameters import validate_public
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
BACKEND=HERE/'build/backend'
SERVER=HERE/'build/full_server'
PBC=0x50424332303234
DESC=struct.Struct('>BQ16sIQQ32s12s16sQ15x')
assert DESC.size==128
def child_cpu():
    r=resource.getrusage(resource.RUSAGE_CHILDREN);return r.ru_utime+r.ru_stime
def xor(a,b):
    if len(a)!=len(b):raise ValueError('share size')
    # Big-int XOR runs in C and retains leading zero bytes.
    return (int.from_bytes(a,'little')^int.from_bytes(b,'little')).to_bytes(len(a),'little')
def u64(x):return struct.pack('!Q',x)
def get64(sock):return struct.unpack('!Q',receive(sock,8))[0]

class FullSession:
    def __init__(self,snapshot:Path,template_expr,*,threads=1):
        start=time.perf_counter();self.snapshot=Path(snapshot)
        self.public=json.loads((self.snapshot/'public.json').read_text())
        if self.public.get('protocol')!='EPBKPIR-TCP-BFS-OCC-v1':raise ValueError('snapshot requires new DO installation')
        validate_public(self.public)
        self.threads=threads;self.epoch=0;self.ready=False;self.last_preprocessing=None
        atoms,gates=compile_query(template_expr,self.public['fields']);self.shape=(atoms,gates)
        self.template=public_template(self.public['N'],len(self.public['fields']),atoms,gates,128)
        for sid in (0,1):
            d=self.snapshot/f's{sid}'
            # Public startup configuration, not an online message carrying intent.
            (d/'template').write_text(self.template)
            p=self.public
            (d/'full-config').write_text(' '.join(map(str,[BACKEND,p['blocks'],p['B'],p['Q'],p['version'],PBC,p['occ_rows'],p['occ_width'],0,threads])))
        env=os.environ.copy();env['IPBM_EVAL_THREADS']=str(threads)
        self.pair=ServerPair([self.snapshot/f's{s}' for s in (0,1)],mode='full-server',engine=SERVER,server_env=env)
        self.initialization={'wall_seconds':time.perf_counter()-start,'servers':self.pair.base_metrics,'client_server_bytes':2}
    def prepare(self):
        if self.ready:raise RuntimeError('unconsumed preprocessing')
        start=time.perf_counter();self.epoch+=1
        for sock in self.pair.sockets:sock.sendall(b'P'+u64(self.epoch))
        for sock in self.pair.sockets:
            if receive(sock,1)!=b'P' or get64(sock)!=self.epoch:raise RuntimeError('preprocessing epoch')
        elapsed=time.perf_counter()-start;metrics=self.pair.metrics();self.ready=True
        commitments=[s['material_commitment'] for s in metrics]
        if commitments[0]!=commitments[1]:raise RuntimeError('joint material mismatch')
        self.last_preprocessing={'wall_seconds':elapsed,'servers':metrics,'client_server_bytes':36,'server_server_bytes':sum(s['preprocessing']['peer_sent_bytes'] for s in metrics),'epoch':self.epoch,'material_commitment':commitments[0]}
        return self.last_preprocessing
    def query(self,expr,output:Path,*,_test_fault=None):
        if not self.ready:raise RuntimeError('fresh preprocessing required')
        self.ready=False;start=time.perf_counter();cp=time.process_time();children=child_cpu()
        output=Path(output);output.mkdir(parents=True,exist_ok=False,mode=0o700)
        prepared=prepare_query(expr,self.public['fields'],output)
        current=public_template(self.public['N'],len(self.public['fields']),prepared['atoms'],prepared['gates'],128)
        if current!=self.template:raise ValueError('query does not conform to installed public template')
        compilegen=time.perf_counter()-start;p=self.public;wire=0;message_sizes=[]
        for sid,sock in enumerate(self.pair.sockets):
            blob=(output/f'fss.{sid}').read_bytes();frame=b'T'+u64(self.epoch)+u64(len(blob))+blob;sock.sendall(frame);wire+=len(frame);message_sizes.append({'direction':f'C>S{sid}','kind':'ipbm_query','bytes':len(frame)})
        counts=[];encodings=[]
        for sid,sock in enumerate(self.pair.sockets):
            m=get64(sock);size=get64(sock)
            expected=0 if not m else bfs.parameters(m)[1]*144
            if not 0<=m<=p['N'] or size!=expected:raise RuntimeError('count/BFS response shape')
            counts.append(m);encodings.append(receive(sock,size));wire+=16+size
            message_sizes += [{'direction':f'S{sid}>C','kind':'m','bytes':8},{'direction':f'S{sid}>C','kind':'bfs_response','bytes':8+size}]
        if counts[0]!=counts[1]:raise RuntimeError('count mismatch')
        m=counts[0];bad=None;descriptions=[];raw_descriptors=[];indices=[];pirprep={};recovermetrics={};pir_recover_rc=None;plaintext=[]
        bfstart=time.perf_counter()
        if m:
            try:
                combined=xor(*encodings)
                if _test_fault=='bfs':combined=bytes(len(combined))
                for raw in bfs.decode(combined,m):
                    valid,version,oid,aad,at,length,key,nonce,tag,count=DESC.unpack(raw)
                    if valid!=1 or version!=p['version'] or count!=(length+p['B']-1)//p['B'] or at+count>p['data_blocks']:raise ValueError('descriptor format/epoch/bounds')
                    descriptions.append((oid,Locator(aad,at,0,length,count,key,nonce,tag)))
                    raw_descriptors.append(raw)
                indices=sorted({i for _,loc in descriptions for i in range(loc.start_block,loc.start_block+loc.block_count)})
                if len(indices)>p['Q']:bad='capacity'
            except ValueError:bad='descriptor'
        bfsseconds=time.perf_counter()-bfstart
        if m:
            targets=[] if bad else indices
            prefix=output/'pir';t=time.perf_counter()
            cmd=[str(BACKEND),'prepare',str(p['blocks']),str(p['B']),str(p['Q']),','.join(map(str,targets)) or '-',str(prefix),'1',str(p['version']),str(PBC),'force_failure' if _test_fault=='schedule' else 'genschedule',str(secrets.randbits(64)),str(p['ls_rank_parameter']),str(p['occ_width']),'0',str(p['occ_rows']),'fixed_explicit']
            prep=subprocess.run(cmd,check=True,capture_output=True,text=True);pirprep=json.loads(prep.stdout);pirprep['client_wall_seconds']=time.perf_counter()-t
            for sid,sock in enumerate(self.pair.sockets):
                key=Path(str(prefix)+f'.s{sid}.keys').read_bytes();sock.sendall(u64(len(key))+key);wire+=8+len(key);message_sizes.append({'direction':f'C>S{sid}','kind':'dpf_keys','bytes':8+len(key)})
            matrices=[]
            # Both complete DPF requests have been generated and sent before
            # the client receives any current-call public matrix randomness.
            for sid,sock in enumerate(self.pair.sockets):
                matrix_size=get64(sock)
                if matrix_size!=p['occ_matrix_bytes']:raise RuntimeError('OCC Setup shape')
                matrix=receive(sock,matrix_size);wire+=8+matrix_size
                if _test_fault=='matrix' and sid==1:matrix=bytes([matrix[0]^1])+matrix[1:]
                matrices.append(matrix);message_sizes.append({'direction':f'S{sid}>C','kind':'occ_setup','bytes':8+matrix_size})
                size=get64(sock)
                if size!=p['occ_rows']*p['B']:raise RuntimeError('OCC shape')
                response=receive(sock,size);wire+=8+size
                if _test_fault=='response' and sid==0:response=bytes([response[0]^1])+response[1:]
                (output/f'response{sid}').write_bytes(response);message_sizes.append({'direction':f'S{sid}>C','kind':'occ_response','bytes':8+size})
            if matrices[0]!=matrices[1]:bad=bad or 'occ_setup'
            (output/'occ-matrix.bin').write_bytes(matrices[0])
            # Client-local fault injection after both fixed-size replies have
            # been consumed; production always uses original meta/response.
            meta=Path(str(prefix)+'.meta')
            if _test_fault in ('rank','epoch'):
                b=bytearray(meta.read_bytes())
                if _test_fault=='rank':b[128+8*p['Q']:128+16*p['Q']]=bytes(8*p['Q'])
                else:struct.pack_into('<Q',b,64,p['version']+1)
                meta.write_bytes(b)
            t=time.perf_counter()
            rec=subprocess.run([str(BACKEND),'recover',str(meta),str(output/'response0'),str(output/'response1'),str(p['B']),str(p['version']),str(output/'blocks'),'paper_faithful_optimized',str(self.threads),'scalar','AEAD','all_slots',str(output/'occ-matrix.bin')],capture_output=True,text=True)
            pir_recover_rc=rec.returncode
            if rec.returncode:bad=bad or 'pir_recovery'
            recovermetrics={'wall_seconds':time.perf_counter()-t,'returncode':rec.returncode,'stdout':rec.stdout,'stderr':rec.stderr}
            if not bad:
                try:
                    recovered=(output/'blocks').read_bytes()
                    if len(recovered)!=p['Q']*p['B']:raise ValueError('block recovery size')
                    blocks={key:recovered[k*p['B']:(k+1)*p['B']] for k,key in enumerate(indices)}
                    # Authenticate all objects before releasing any plaintext.
                    plaintext=[(oid,recover_object(loc,blocks,p['B'])) for oid,loc in descriptions]
                except Exception:bad='authentication'
        files=[]
        if not bad:
            for oid,data in plaintext:
                f=output/(oid.hex()+'.bin');f.write_bytes(data);files.append(str(f))
            (output/'descriptors.bin').write_bytes(b''.join(raw_descriptors))
        end=time.perf_counter();clientcpu=time.process_time()-cp+child_cpu()-children
        metrics=self.pair.metrics() # observer only, outside measured endpoint
        result={'status':'PRIVATE_RETRIEVAL_FAILED' if bad else 'ok','failure_diagnostic_local':bad,'files':files,'m':m,'target_blocks':len(indices),'Q':p['Q'],'epoch':self.epoch,'online_seconds':end-start,'completion_monotonic_seconds':end,'client_cpu_seconds':clientcpu,'query_generation_seconds':compilegen,'bfs_decode_seconds':bfsseconds,'bfs_decode_calls':int(bool(m)),'servers':metrics,'pir_prepare':pirprep,'pir_recover':recovermetrics,'client_server_bytes':wire,'server_server_bytes':sum(s['peer_sent_bytes'] for s in metrics),'messages':message_sizes,'preprocessing':self.last_preprocessing,'initialization':self.initialization,'global_pir_batches':int(bool(m)),'transport':'REAL_TCP_LOOPBACK','material_ready':True,'public':p}
        result['descriptors_file']=str(output/'descriptors.bin') if not bad else None
        result['authorized_descriptions']=len(descriptions)
        (output/'result.json').write_text(json.dumps(result,indent=2));return result
    def close(self):
        self.pair.mode='retrieval-server';self.pair.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def query(snapshot,expr,output,**kwargs):
    """Default cold request: wall time includes session + fresh materials."""
    start=time.perf_counter()
    with FullSession(snapshot,expr) as session:
        session.prepare();result=session.query(expr,output,_test_fault='schedule' if kwargs.get('force_route_failure') else None)
        result['cold_request_seconds']=result['completion_monotonic_seconds']-start
        (Path(output)/'result.json').write_text(json.dumps(result,indent=2))
        return result
