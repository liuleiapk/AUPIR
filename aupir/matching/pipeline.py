"""DO snapshot preparation and C-only query interface. Local process transport."""
from __future__ import annotations
import json, os, secrets, shlex, shutil, struct, subprocess, sys, time, resource
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from aupir.layout import build_database, LayoutKind, Locator, recover_object
HERE=Path(__file__).resolve().parent
ENGINE=HERE/'engine'
BACKEND=ROOT/'backend/build/backend'
DESC=struct.Struct('>BQ16sIQQ32s12s16s23x')
assert DESC.size==128
from aupir.matching.compiler import compile_query, public_template
from aupir.matching.transport import ServerPair, prepare_query
PBC=0x50424332303234

def xor(a,b):
    if len(a)!=len(b): raise ValueError('share length mismatch')
    return bytes(x^y for x,y in zip(a,b))

def child_cpu_total():
    usage=resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime+usage.ru_stime

def prepare_legacy(root:Path, rows, contents, fields, *, block_size=64, capacity=8, version=1, object_order=None):
    """DO only. Each server receives table, own descriptor shares, whole image."""
    if len(rows)!=len(contents) or not rows or capacity<2: raise ValueError('snapshot')
    if block_size<1 or not fields or any(not 1<=v['bits']<=32 for v in fields.values()):raise ValueError('public field/block parameters')
    if any(not isinstance(row[f],int) or not 0<=row[f]<(1<<spec['bits']) for row in rows for f,spec in fields.items()):raise ValueError('attribute outside encoded domain')
    root.mkdir(parents=True,exist_ok=False)
    if object_order is None:
        order=list(range(len(rows)));secrets.SystemRandom().shuffle(order)
    else:
        # DO may supply its private permutation to control snapshot placement.
        # It is never included in either server's public metadata.
        order=list(object_order)
        if sorted(order)!=list(range(len(rows))):raise ValueError('object permutation')
    db=build_database([contents[i] for i in order],block_size,LayoutKind.ALIGNED,capacity)
    desc=[None]*len(rows)
    for pos,row in enumerate(order):
        loc=db.locators[pos]
        desc[row]=DESC.pack(1,version,secrets.token_bytes(16),loc.logical_index,loc.start_block,loc.true_length,loc.key,loc.nonce,loc.tag)
    clear=b''.join(desc);share=secrets.token_bytes(len(clear))
    public={'N':len(rows),'fields':fields,'B':block_size,'Q':capacity,'version':version,'blocks':len(db.blocks),'descriptor_bytes':DESC.size}
    (root/'public.json').write_text(json.dumps(public))
    for sid,part in enumerate((share,xor(share,clear))):
        d=root/f's{sid}';d.mkdir(mode=0o700)
        (d/'table').write_text('\n'.join(' '.join(str(row[f]) for f in fields) for row in rows))
        (d/'descriptions').write_bytes(part)
        (d/'database.img').write_bytes(b''.join(db.blocks))
        (d/'public.json').write_text(json.dumps(public))
        # No locators, keys, lengths, file boundaries or per-file manifests.
        (d/'backend-command').write_text(shlex.join([sys.executable,str(HERE/'backend_worker.py'),str(d.resolve())]))
    return public

def query_legacy(root:Path,expr,output:Path,*,force_route_failure=False,transport_options=None):
    """C inputs only public parameters and private predicate. No row/ID output."""
    request_start=time.perf_counter()
    client_cpu_start=time.process_time()
    p=json.loads((root/'public.json').read_text())
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    keygen_cpu_before=child_cpu_total()
    prepared=prepare_query(expr,p['fields'],output)
    keygen_total_cpu=child_cpu_total()-keygen_cpu_before
    atoms,gates=prepared['atoms'],prepared['gates']
    template=public_template(p['N'],len(p['fields']),atoms,gates,DESC.size)
    for sid in (0,1):(root/f's{sid}'/'template').write_text(template)
    query_preparation_seconds=time.perf_counter()-request_start
    pair=None
    try:
        pair=ServerPair([root/f's{sid}' for sid in (0,1)],mode='server',**(transport_options or {}))
        preprocessing_seconds,preprocessing=pair.prepare()
        online_seconds,m,retrieval_metrics,_=pair.run(prepared['frames'])
        # Actual request boundary: includes materials prepared AFTER this request,
        # session/base OT, compile/Gen/assembly, transmission, and m delivery.
        retrieval_wait_seconds=time.perf_counter()-request_start
        if not 0<=m<=p['N']:raise RuntimeError('count domain')
        for server in pair.servers:
            server.stdin.write('DESCRIBE\n');server.stdin.flush()
        for sid,server in enumerate(pair.servers):
            if server.stdout.readline().strip()!='READY':
                raise RuntimeError((root/f's{sid}'/'retrieval.stderr').read_text())
        selected=xor(*( (root/f's{i}'/'selected').read_bytes() for i in range(2)))
        if len(selected)!=p['N']*DESC.size:raise RuntimeError('description response shape')
        descriptions=[];valid_descriptions=[]
        for at in range(0,len(selected),DESC.size):
            raw=selected[at:at+DESC.size]
            if raw==bytes(DESC.size):continue
            valid,version,oid,aad,start,length,key,nonce,tag=DESC.unpack(raw)
            count=(length+p['B']-1)//p['B']
            if valid!=1 or version!=p['version'] or start+count>p['blocks']-p['Q']:raise RuntimeError('invalid description')
            valid_descriptions.append(raw)
            descriptions.append((oid,Locator(aad,start,0,length,count,key,nonce,tag)))
        if len(descriptions)!=m:raise RuntimeError('description count differs from retrieval m')
        (output/'descriptions.bin').write_bytes(b''.join(valid_descriptions))
        indices=list(dict.fromkeys(k for _,loc in descriptions for k in range(loc.start_block,loc.start_block+loc.block_count)))
        secrets.SystemRandom().shuffle(indices)
        overflow=len(indices)>p['Q'];targets=[] if overflow else list(indices)
        # Use the Q physical dummy blocks provisioned by DO, including for
        # empty/overflow batches. No clear keyword list is sent to servers.
        targets += list(range(p['blocks']-p['Q'],p['blocks']-p['Q']+p['Q']-len(targets)))
        secrets.SystemRandom().shuffle(targets)
        prefix=output/'pir'
        cmd=[str(BACKEND),'prepare',str(p['blocks']),str(p['B']),str(p['Q']),','.join(map(str,targets)) or '-',str(prefix),'0',str(p['version']),str(PBC),'force_failure' if force_route_failure else 'genschedule',str(secrets.randbits(64)),'40','128','881','0','fixed']
        child_cpu=lambda: resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime+resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime
        cpu_before=child_cpu();pir_prepare_start=time.perf_counter()
        prep=subprocess.run(cmd,check=True,capture_output=True,text=True)
        pir_prepare_seconds=time.perf_counter()-pir_prepare_start;pir_prepare_cpu=child_cpu()-cpu_before
        for sid in range(2):
            shutil.copyfile(str(prefix)+f'.s{sid}.keys',root/f's{sid}'/'pir.keys')
            pair.servers[sid].stdin.write('PIR\n');pair.servers[sid].stdin.flush()
        metrics=[];server_tree_cpu=[]
        for sid,s in enumerate(pair.servers):
            tree_cpu_before=child_cpu_total()
            out,err=s.communicate(timeout=120)
            server_tree_cpu.append(child_cpu_total()-tree_cpu_before)
            if s.returncode:raise RuntimeError((root/f's{sid}'/'retrieval.stderr').read_text()+out)
            metrics.append(json.loads(out.splitlines()[-1]))
        recover_start=time.perf_counter();cpu_before=child_cpu()
        recover=subprocess.run([str(BACKEND),'recover',str(prefix)+'.meta',str(root/'s0/response'),str(root/'s1/response'),str(p['B']),str(p['version']),str(output/'blocks'),'paper_faithful_optimized','1','scalar','AEAD','all_slots'],capture_output=True,text=True)
        pir_recover_cpu=child_cpu()-cpu_before
        if recover.returncode not in (0,46):raise RuntimeError(recover.stderr)
        failure='capacity' if overflow else 'routing' if recover.returncode else None
        files=[]
        if not failure:
            recovered=(output/'blocks').read_bytes();blocks={k:recovered[i*p['B']:(i+1)*p['B']] for i,k in enumerate(targets)}
            # Authenticate all objects before publishing any file.
            plaintext=[(oid,recover_object(loc,blocks,p['B'])) for oid,loc in descriptions]
            for oid,data in plaintext:
                f=output/(oid.hex()+'.bin');f.write_bytes(data);files.append(f)
        result={'status':failure or 'ok','files':[str(f) for f in files],'authorized_descriptions':len(descriptions),'descriptions_file':str(output/'descriptions.bin'),'target_blocks':len(indices),'Q':p['Q'],'servers':metrics,'pir_request_bytes':[(root/f's{i}/pir.keys').stat().st_size for i in range(2)],'pir_response_bytes':[(root/f's{i}/response').stat().st_size for i in range(2)],'transport':'LOCAL_PROCESSES_PRIVATE_PATHS_NOT_CROSS_HOST_TLS','fss_atoms':len(atoms),'global_pir_batches':1,'external_messages_per_server':{'fss_request':1,'m_response':1,'description_response':1,'pir_request':1,'pir_response':1},'fss_request_bytes':[len(frame) for frame in prepared['frames']], 'm':m, 'retrieval_servers':retrieval_metrics, 'retrieval_preprocessing':preprocessing, 'retrieval_session_servers':pair.base_metrics, 'retrieval_timing':{'query_preparation_seconds':query_preparation_seconds,'compile_seconds':prepared['compile_seconds'],'keygen_process_seconds':prepared['keygen_process_seconds'],'keygen_seconds':prepared['keygen']['keygen_seconds'],'session_seconds':pair.session_seconds,'preprocessing_seconds':preprocessing_seconds,'online_seconds':online_seconds,'request_wait_seconds':retrieval_wait_seconds}, 'retrieval_query_hashes':prepared['hashes'], 'retrieval_binary_steps':len(gates), 'retrieval_dcf_pairs':2*len(atoms)}
        result['retrieval_peer_endpoint']=pair.servers[0].args[-2]
        # Actual local protocol control, separate from observer metric JSON:
        # C->S DESCRIBE\n (9), S->C READY\n (6), C->S PIR\n (4).
        result['protocol_control_bytes_per_server']=len(b'DESCRIBE\n')+len(b'READY\n')+len(b'PIR\n')
        result['full_online_seconds']=time.perf_counter()-request_start
        result['client_cpu_seconds']=time.process_time()-client_cpu_start+keygen_total_cpu+pir_prepare_cpu+pir_recover_cpu
        result['server_process_tree_cpu_seconds']=server_tree_cpu
        result['pir_prepare_seconds']=pir_prepare_seconds
        result['client_recovery_seconds']=time.perf_counter()-recover_start
        result['pir_prepare_stdout']=prep.stdout
        result['pir_recover_stdout']=recover.stdout
        result['backend_servers']=[json.loads((root/f's{i}/backend-resource.json').read_text()) for i in range(2)]
        (output/'result.json').write_text(json.dumps(result,indent=2));return result
    finally:
        if pair is not None:pair.close()

# Default full-protocol entry points. The historical file bridge remains
# explicitly named for reproducing old experiments; never a failure fallback.
def prepare(*args,**kwargs):
    from aupir.online.install import prepare as install
    return install(*args,**kwargs)

def query(*args,**kwargs):
    from aupir.online.session import query as execute
    return execute(*args,**kwargs)
