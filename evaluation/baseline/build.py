#!/usr/bin/env python3
"""Build the independent baseline harness with the production compiler/link options."""
import hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
K=os.environ.get('KUNLUN_ROOT')
cfgs=[HERE/'worker',HERE/'build.py',ROOT/'evaluation/baseline/legacy_engine_20261114.h',ROOT/'epbkpir/matching/dcf_bit_eval.h']
if K:cfgs.append(Path(K)/'mpc/p2frpsu/DCF/DCFClient.cpp')
m=json.loads((ROOT/'epbkpir/matching/build_manifest.json').read_text())
cmd=m['command'][:]
cmd[cmd.index(str(ROOT/'epbkpir/matching/engine.cpp'))]=str(HERE/'worker.cpp')
cmd[cmd.index('-o')+1]=str(HERE/'worker')
subprocess.run(cmd,check=True)
inputs=[Path(x) for x in cmd if x.endswith(('.cpp','.a','.so')) and Path(x).is_file()]
inputs += cfgs
(HERE/'build_manifest.json').write_text(json.dumps({'command':cmd,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}},indent=2))
