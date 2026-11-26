#!/usr/bin/env python3
"""Build against installed, real DCF/DPF and libOTe; no mock fallback."""
import os, shlex, subprocess, hashlib, json, argparse
from pathlib import Path
HERE=Path(__file__).resolve().parent
ap=argparse.ArgumentParser();ap.add_argument('--test-dcf',action='store_true');ap.add_argument('--validation',action='store_true');args=ap.parse_args()
K=Path(os.environ['KUNLUN_ROOT']) if os.environ.get('KUNLUN_ROOT') else None
W=Path(os.environ['WALDO_ROOT']) if os.environ.get('WALDO_ROOT') else None
R=Path(os.environ['RELIC_ROOT']) if os.environ.get('RELIC_ROOT') else None
if K is None or W is None or R is None:
    raise SystemExit('Set KUNLUN_ROOT, WALDO_ROOT and RELIC_ROOT first; no protocol fallback')
O=W/'fss-core/libOTe'
flags=K/'mpc/p2frpsu/revision_20261026/dcf_optimization/build/CMakeFiles/test_circular_dcf.dir'
if not flags.exists(): raise SystemExit('Missing real DCF dependency under KUNLUN_ROOT; no protocol fallback')
f=(flags/'flags.make').read_text().splitlines()
get=lambda n: shlex.split(next(x.split(' = ',1)[1] for x in f if x.startswith(n+' = ')))
link=shlex.split((flags/'link.txt').read_text()); libs=link[link.index('-o')+2:]
base=flags.parents[1]
libs=[str(base/x) if not x.startswith(('/','-')) else x for x in libs]
cmd=['g++',*get('CXX_DEFINES'),*get('CXX_INCLUDES'),*get('CXX_FLAGS'),'-include','immintrin.h','-std=c++17','-DENABLE_IKNP','-I'+str(W),'-I'+str(W/'fss-core/DPF-source'),str(HERE/'engine.cpp'),str(O/'libOTe/TwoChooseOne/IknpOtExtSender.cpp'),str(O/'libOTe/TwoChooseOne/IknpOtExtReceiver.cpp'),str(W/'fss-core/DPF-source/DPFClient.cpp'),str(W/'fss-core/DPF-source/DPFServer.cpp'),'-o',str(HERE/'engine'),*libs]
cmd += ['-Wl,-rpath,'+str(R/'lib'),str(R/'lib/librelic.so')]
subprocess.run(cmd,check=True)

inputs=[HERE/'engine.cpp',HERE/'retrieval.h',HERE/'compiler.py',HERE/'pipeline.py',HERE/'transport.py',HERE/'dcf_bit_eval.h',K/'mpc/p2frpsu/DCF/DCFClient.cpp',K/'mpc/p2frpsu/DCF/DCFServer.cpp',O/'libOTe/TwoChooseOne/IknpOtExtSender.cpp',O/'libOTe/TwoChooseOne/IknpOtExtReceiver.cpp',W/'fss-core/DPF-source/DPFClient.cpp',W/'fss-core/DPF-source/DPFServer.cpp',HERE/'engine',R/'lib/librelic.so',*[Path(p) for p in libs if p.endswith('.a')]]
(HERE/'build_manifest.json').write_text(json.dumps({'command':cmd,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}},indent=2))

if args.validation:
    validation_cmd=cmd[:]
    validation_cmd.insert(1,'-DIPBM_TEST_EXPORT')
    validation_cmd[validation_cmd.index('-o')+1]=str(HERE/'engine_validation')
    subprocess.run(validation_cmd,check=True)
    (HERE/'validation_build_manifest.json').write_text(json.dumps({'command':validation_cmd,'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*inputs,HERE/'engine_validation']}},indent=2))

if args.test_dcf:
    test_cmd=cmd[:]
    test_cmd[test_cmd.index(str(HERE/'engine.cpp'))]=str(HERE/'test_dcf_eval.cpp')
    test_cmd[test_cmd.index('-o')+1]=str(HERE/'test_dcf_eval')
    subprocess.run(test_cmd,check=True)
