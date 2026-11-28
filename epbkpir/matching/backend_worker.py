"""Server-only adapter; no client access to unmasked response."""
import json,subprocess,sys,time,resource
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from epbkpir.matching.pipeline import BACKEND,PBC
root=Path(sys.argv[1]);p=json.loads((root/'public.json').read_text())
cmd=[str(BACKEND),'serve','indirected_file',str(p['blocks']),str(p['B']),str(p['Q']),str(p['B']),str(p['version']),str(PBC),'local','paper_faithful_optimized','1','scalar','row_major','fixed',str(root/'database.img')]
start=time.perf_counter()
r=subprocess.run(cmd,input=f'{root}/pir.keys {root}/raw-response\nQUIT\n',text=True,capture_output=True,check=True)
(root/'backend-resource.json').write_text(json.dumps({'wall_seconds':time.perf_counter()-start,'child_user_cpu_seconds':resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime,'child_system_cpu_seconds':resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime,'worker_cpu_seconds':time.process_time(),'stdout':r.stdout}))
(root/'backend-metrics.json').write_text(r.stdout)
