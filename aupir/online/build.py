"""Build the AUPIR online server binaries from the matching-core build recipe."""
import hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
out=HERE/'build';out.mkdir(exist_ok=True)
manifest=json.loads((ROOT/'aupir/matching/build_manifest.json').read_text())
cmd=manifest['command'][:]
cmd[cmd.index(str(ROOT/'aupir/matching/engine.cpp'))]=str(HERE/'full_server.cpp')
cmd[cmd.index('-o')+1]=str(out/'full_server')
cmd+=['-lcrypto']
subprocess.run(cmd,check=True)
vendor=Path(os.environ.get('TMPDIR','/tmp'))/'two-server-dpf-cpp/src'
if not vendor.exists():raise SystemExit('Run backend/build.sh first: dpf-cpp sources not found under TMPDIR/two-server-dpf-cpp/src')
backend=['g++','-O3','-DNDEBUG','-std=c++17','-maes','-msse2','-msse4.1','-mavx2','-mpclmul','-pthread','-Wno-ignored-attributes','-I'+str(vendor),str(ROOT/'backend/backend.cpp'),*[str(vendor/f) for f in ['AES.cpp','Defines.cpp','Log.cpp','PRNG.cpp','dpf.cpp']],'-lcrypto','-o',str(out/'backend')]
subprocess.run(backend,check=True)
subprocess.run([str(out/'backend'),'selftest'],check=True)
files=[HERE/'full_server.cpp',ROOT/'aupir/matching/retrieval.h',ROOT/'backend/backend.cpp',out/'backend',out/'full_server']
(out/'manifest.json').write_text(json.dumps({'commands':[cmd,backend],'sha256':{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}},indent=2))
