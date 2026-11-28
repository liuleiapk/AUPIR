import argparse,json,tempfile
from pathlib import Path
from .pipeline import prepare,query

def main():
    ap=argparse.ArgumentParser(description='EPBKPIR: IPBM -> private BFS descriptors -> Batch PIR/OCC over TCP')
    ap.add_argument('--prepare-json',type=Path);ap.add_argument('--snapshot',type=Path);ap.add_argument('--predicate-json',type=Path);ap.add_argument('--output-dir',type=Path);ap.add_argument('--demo',action='store_true')
    a=ap.parse_args()
    if a.prepare_json:
        if not a.snapshot:ap.error('--snapshot required for DO preparation')
        data=json.loads(a.prepare_json.read_text());records=data['records']
        paths=[a.prepare_json.parent/r['file'] for r in records]
        print(json.dumps(prepare(a.snapshot,[r['attributes'] for r in records],[p.read_bytes() for p in paths],data['fields'],block_size=data.get('block_size',65536),capacity=data['capacity'])))
        return
    if not a.output_dir:ap.error('--output-dir required for query')
    if a.demo:
        with tempfile.TemporaryDirectory(prefix='fss-demo-') as t:
            root=Path(t)/'snapshot'
            rows=[{'sex':s,'age':age} for s,age in [(1,34),(1,35),(1,36),(0,36),(1,50)]]
            prepare(root,rows,[f'file: sex={r["sex"]}, age={r["age"]}\n'.encode() for r in rows],{'sex':{'bits':1,'encoding':{'女':0,'男':1}},'age':{'bits':32}},capacity=8)
            print(json.dumps(query(root,('AND',('EQ','sex',1),('GT','age',35)),a.output_dir),ensure_ascii=False))
    else:
        if not a.snapshot or not a.predicate_json:ap.error('--snapshot and --predicate-json required')
        print(json.dumps(query(a.snapshot,json.loads(a.predicate_json.read_text()),a.output_dir),ensure_ascii=False))
if __name__=='__main__':main()
