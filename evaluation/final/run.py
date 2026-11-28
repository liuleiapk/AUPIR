#!/usr/bin/env python3
"""Validate the final production core and time ONLY the two specified queries.

Performance uses the actual default `engine server` path through m delivery,
then stops before descriptors. Each request starts its own session and fresh
materials, matching pipeline.query. No A/B comparison is performed.
"""
from __future__ import annotations
import argparse,hashlib,json,os,platform,random,statistics,subprocess,sys,time
from collections import defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from epbkpir.matching.compiler import compile_query,public_template
from epbkpir.matching.transport import ServerPair,prepare_query,ENGINE
from evaluation.final.cases import cases,vector,WORKLOADS


def deploy(root,rows,fields,atoms,gates):
    root.mkdir(parents=True,exist_ok=True)
    text='\n'.join(' '.join(str(row[field]) for field in fields) for row in rows)
    template=public_template(len(rows),len(fields),atoms,gates)
    dirs=[]
    for sid in (0,1):
        d=root/f's{sid}';d.mkdir(exist_ok=True,mode=0o700)
        (d/'table').write_text(text);(d/'template').write_text(template);dirs.append(d)
    return dirs


def complexity(n,atoms,gates):
    p,g=len(atoms),len(gates)
    # IKNP sends matrices in 1024-OT superblocks, each 16384 bytes. These
    # configurations need one matrix message per direction per extension.
    matrix=16384*((n+1023)//1024)
    return dict(n=n,conditions=p,binary_steps=g,bits=[a[1] for a in atoms],
        dcf_key_pairs=2*p,dcf_keys_per_server=2*p,dcf_evaluations_per_server=2*p*n,
        query_body_bytes_per_server=12+sum(9+48*(a[1]+1) for a in atoms)+9*g,
        query_frame_bytes_per_server=17+sum(9+48*(a[1]+1) for a in atoms)+9*g,
        public_template_bytes_per_server=len(public_template(n,2,atoms,gates).encode()),
        fresh_boolean_triples=n*g,fresh_boolean_random_ots=2*n*g,fresh_count_random_ots=n,
        boolean_logical_opening_bits=4*n*g,boolean_serialized_payload_bytes=4*n*g,
        boolean_online_framed_bytes=4*n*g+8*g,
        count_online_payload_bytes=17*n+16,count_online_framed_bytes=17*n+32,
        m_to_client_bytes=16,boolean_online_rounds=g,count_online_dependency_rounds=3,
        triple_preprocessing_framed_bytes=g*(64*n+2*matrix+16)+10,
        count_preprocessing_framed_bytes=matrix+14,
        preprocessing_stat_barrier_bytes=20)


def check(sample,expected,n,atoms,gates):
    assert sample['m']==sum(expected)
    c=complexity(n,atoms,gates);metrics=sample['servers'];pre=sample['preprocessing']
    assert sample['query_bytes']==[c['query_frame_bytes_per_server']]*2
    assert sum(m['boolean_sent_bytes'] for m in metrics)==c['boolean_online_framed_bytes']
    assert sum(m['count_sent_bytes'] for m in metrics)==c['count_online_framed_bytes']
    assert sum(m['triple_sent_bytes'] for m in pre)==c['triple_preprocessing_framed_bytes']
    assert sum(m['count_random_ot_sent_bytes'] for m in pre)==c['count_preprocessing_framed_bytes']
    assert all(m['dcf_evaluations']==c['dcf_evaluations_per_server'] for m in metrics)
    assert all(m['fresh_boolean_triples']==c['fresh_boolean_triples'] and m['fresh_count_random_ots']==n for m in pre)
    assert all(m['m']==sample['m'] for m in metrics)


def validate(out):
    reports=[];hashes=set();shapes={};maximum_count_cases=defaultdict(int)
    for bits in (1,2,3,4,8,32):
        fields={'value':{'bits':bits},'sex':{'bits':1}}
        values=range(1<<bits) if bits<=8 else (0,1,2,34,35,36,100,2**32-2,2**32-1)
        rows=[{'value':x,'sex':s} for x in values for s in (0,1)]
        grouped=defaultdict(list)
        for name,expr in cases(bits):
            a,g=compile_query(expr,fields)
            grouped[public_template(len(rows),len(fields),a,g)].append((name,expr,a,g))
        for group_index,(template,items) in enumerate(grouped.items()):
            root=out/f'b{bits}-template{group_index}';dirs=deploy(root,rows,fields,items[0][2],items[0][3]);client=root/'client';client.mkdir()
            pair=ServerPair(dirs,engine=ENGINE.with_name('engine_validation'))
            try:
                for index,(name,expr,a,g) in enumerate(items):
                    prepared=prepare_query(expr,fields,client,engine=ENGINE.with_name('engine_validation'),validation=True)
                    prep_s,pre=pair.prepare();online,m,metrics,z=pair.run(prepared['frames'],validation_n=len(rows))
                    expected=vector(expr,rows);assert z==expected,(bits,name)
                    sample=dict(m=m,query_bytes=[len(f) for f in prepared['frames']],servers=metrics,preprocessing=pre)
                    check(sample,expected,len(rows),a,g)
                    assert all(p['material_epoch']==index+1 for p in pre)
                    assert not any(h in hashes for h in prepared['hashes']);hashes.update(prepared['hashes'])
                    shape=tuple(sample['query_bytes']);shapes.setdefault(template,shape);assert shapes[template]==shape
                    for label,target in (('zero',0),('one',1),('all',len(rows))):
                        if m==target:maximum_count_cases[label]+=1
                    reports.append(dict(bits=bits,case=name,conditions=len(a),binary_steps=len(g),m=m,n=len(rows),passed=True))
            finally:pair.close()
        print(json.dumps({'validation_bits':bits,'cases':sum(len(x) for x in grouped.values())}),flush=True)
    # A production server must reject the test-only share-export frame.
    f={'value':{'bits':1}};expr=('EQ','value',0);a,g=compile_query(expr,f)
    root=out/'production-export-guard';dirs=deploy(root,[{'value':0}],f,a,g);client=root/'client';client.mkdir()
    pair=ServerPair(dirs)
    rejected=False
    try:
        prepared=prepare_query(expr,f,client,validation=True);pair.prepare()
        try:pair.run(prepared['frames'],validation_n=1)
        except (RuntimeError,ConnectionError):rejected=True
    finally:pair.close()
    assert rejected
    report=dict(passed=True,cases=len(reports),vector_and_count_checked=True,query_hashes_unique=True,
        same_template_shapes_checked=True,production_share_export_rejected=True,m_cases=dict(maximum_count_cases),results=reports)
    (out/'validation.json').write_text(json.dumps(report,indent=2))


def summarize(samples):
    median=statistics.median
    client=lambda k:median(s[k] for s in samples)*1000
    critical=lambda phase,k:median(max(m[k] for m in s[phase]) for s in samples)*1000
    return dict(query_preparation_ms=client('query_preparation_seconds'),compile_ms=client('compile_seconds'),
        keygen_ms=median(s['keygen']['keygen_seconds'] for s in samples)*1000,
        session_ms=client('session_seconds'),base_ot_ms=critical('base','base_ot_seconds'),
        preprocessing_ms=client('preprocessing_seconds'),triple_ms=critical('preprocessing','triple_seconds'),
        count_random_ot_ms=critical('preprocessing','count_random_ot_seconds'),
        comparison_ms=critical('servers','evaluation_seconds'),boolean_ms=critical('servers','boolean_seconds'),count_ms=critical('servers','count_seconds'),
        online_ms=client('online_seconds'),online_min_ms=min(s['online_seconds'] for s in samples)*1000,
        online_max_ms=max(s['online_seconds'] for s in samples)*1000,
        request_wait_ms=client('request_wait_seconds'),request_wait_min_ms=min(s['request_wait_seconds'] for s in samples)*1000,
        request_wait_max_ms=max(s['request_wait_seconds'] for s in samples)*1000,
        retrieval_cpu_sum_ms=median(sum(m['cpu_seconds'] for m in s['servers']) for s in samples)*1000,
        preprocessing_cpu_sum_ms=median(sum(m['cpu_seconds'] for m in s['preprocessing']) for s in samples)*1000,
        base_ot_cpu_sum_ms=median(sum(m['cpu_seconds'] for m in s['base']) for s in samples)*1000)


def benchmark(out,repeats,warmups):
    hist=ROOT/'artifacts/baseline_20261114/results.json'
    historical=json.loads(hist.read_text()) if hist.exists() else None
    results=[];hashes=set()
    for n in (10000,100000):
        rng=random.Random(20261109);raw=[[rng.randrange(2),rng.randrange(101)] for _ in range(n)]
        raw[:8]=[[1,34],[1,35],[1,36],[0,36],[1,50],[0,0],[1,2**32-1],[0,2**32-2]]
        rows=[dict(sex=s,age=x) for s,x in raw];fields={'sex':{'bits':1},'age':{'bits':32}}
        data_hash=hashlib.sha256(json.dumps(raw).encode()).hexdigest()
        for workload,expr in WORKLOADS.items():
            reference=next((x for x in historical if x['n']==n and x['workload']==workload),None) if historical else None
            expected=vector(expr,rows)
            if reference is not None:assert reference['data_sha256']==data_hash and reference['m']==sum(expected)
            atoms,gates=compile_query(expr,fields)
            root=out/f'{n}-{workload}';dirs=deploy(root,rows,fields,atoms,gates);client=root/'client';client.mkdir();samples=[]
            # Untimed vector validation on the SAME scaled data and production
            # core. The default binary itself has no share-export capability.
            validation_pair=ServerPair(dirs,engine=ENGINE.with_name('engine_validation'))
            try:
                prepared=prepare_query(expr,fields,client,engine=ENGINE.with_name('engine_validation'),validation=True)
                validation_pair.prepare()
                _,m,_,z=validation_pair.run(prepared['frames'],validation_n=n)
                assert z==expected and (reference is None or m==reference['m'])
                workload_validation=dict(passed=True,n=n,m=m,expected_vector_sha256=hashlib.sha256(expected).hexdigest(),
                    observed_vector_sha256=hashlib.sha256(z).hexdigest(),historical_data_sha256=data_hash)
                (root/'workload_validation.json').write_text(json.dumps(workload_validation,indent=2))
            finally:validation_pair.close()
            for index in range(warmups+repeats):
                start=time.perf_counter()
                prepared=prepare_query(expr,fields,client)
                template=public_template(n,len(fields),prepared['atoms'],prepared['gates'])
                for d in dirs:(d/'template').write_text(template)
                preparation=time.perf_counter()-start
                pair=None
                try:
                    pair=ServerPair(dirs,mode='server')
                    prep_s,pre=pair.prepare()
                    online,m,metrics,_=pair.run(prepared['frames'])
                    actual_wait=time.perf_counter()-start
                    sample=dict(index=index,warmup=index<warmups,m=m,query_preparation_seconds=preparation,
                        compile_seconds=prepared['compile_seconds'],keygen=prepared['keygen'],
                        keygen_process_seconds=prepared['keygen_process_seconds'],session_seconds=pair.session_seconds,
                        base=pair.base_metrics,preprocessing_seconds=prep_s,preprocessing=pre,
                        online_seconds=online,request_wait_seconds=actual_wait,servers=metrics,
                        query_bytes=[len(f) for f in prepared['frames']],query_hashes=prepared['hashes'])
                    check(sample,expected,n,atoms,gates)
                    assert not any(h in hashes for h in prepared['hashes']);hashes.update(prepared['hashes'])
                    if index>=warmups:samples.append(sample)
                finally:
                    if pair:pair.close()
            results.append(dict(n=n,workload=workload,expr=expr,m=sum(expected),data_sha256=data_hash,
                historical_matches_verified=(reference is not None),workload_vector_validation=workload_validation,complexity=complexity(n,atoms,gates),summary=summarize(samples),samples=samples))
            (out/'results.json').write_text(json.dumps(results,indent=2))
            print(json.dumps(dict(n=n,workload=workload,summary=results[-1]['summary'])),flush=True)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--validate',action='store_true');ap.add_argument('--validation-only',action='store_true')
    ap.add_argument('--repeats',type=int,default=11);ap.add_argument('--warmups',type=int,default=2);args=ap.parse_args()
    if args.repeats<5:ap.error('at least 5 measured samples')
    args.out.mkdir(parents=True,exist_ok=False);os.sched_setaffinity(0,{0,1,2,3})
    for key in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','YACL_NUM_THREADS'):os.environ[key]='1'
    config=dict(command=[sys.executable,*sys.argv],transport='LOCAL_LOOPBACK_TCP_NO_TLS',timing='DEFAULT_COLD_SESSION_REQUEST_MATERIALS_GENERATED_AFTER_REQUEST',
        cpus=sorted(os.sched_getaffinity(0)),compute_threads_per_server=1,io_service_threads_per_server=1,platform=platform.platform(),
        cpu_model=subprocess.check_output(['lscpu'],text=True),warmups=args.warmups,repeats=args.repeats,
        production_build=json.loads((ROOT/'epbkpir/matching/build_manifest.json').read_text()),
        validation_build=json.loads((ROOT/'epbkpir/matching/validation_build_manifest.json').read_text()),
        runner_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('cases.py')]})
    (args.out/'config.json').write_text(json.dumps(config,indent=2))
    if args.validate or args.validation_only:validate(args.out)
    if not args.validation_only:benchmark(args.out,args.repeats,args.warmups)

if __name__=='__main__':main()
