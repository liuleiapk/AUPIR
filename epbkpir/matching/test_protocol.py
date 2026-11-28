"""Actual two-process protocol tests. Plaintext oracle is confined to tests."""
import json,tempfile,unittest,struct
from pathlib import Path
from .pipeline import prepare,query,compile_query,DESC,ENGINE,xor
FIELDS={'sex':{'bits':1},'age':{'bits':32}}
ROWS=[{'sex':s,'age':a} for s,a in [(1,34),(1,35),(1,36),(0,36),(1,50),(1,0),(0,2**32-1)]]
DATA=[bytes([65+i])*(i*31+1) for i in range(len(ROWS))]
def oracle(e,r):
    op=e[0]
    if op=='EQ':return r[e[1]]==e[2]
    if op=='LT':return r[e[1]]<e[2]
    if op=='GT':return r[e[1]]>e[2]
    if op=='GE':return r[e[1]]>=e[2]
    if op=='LE':return r[e[1]]<=e[2]
    if op=='NE':return r[e[1]]!=e[2]
    if op=='NOT':return not oracle(e[1],r)
    a,b=oracle(e[1],r),oracle(e[2],r)
    return {'AND':a and b,'OR':a or b}[op]
class ProtocolTests(unittest.TestCase):
    def test_real_protocol(self):
        cases=[('accept',('AND',('EQ','sex',1),('GT','age',35))),('less',('LT','age',35)),('or',('OR',('EQ','sex',0),('GT','age',35))),('not',('NOT',('GT','age',35))),('zero',('LT','age',0)),('max',('GT','age',2**32-1)),('boundary',('LT','age',2**32-1)),('equalmax',('EQ','age',2**32-1)),('gtzero',('GT','age',0)),('eqzero',('EQ','age',0)),('ltone',('LT','age',1)),('nested',('OR',('AND',('EQ','sex',1),('GT','age',35)),('NOT',('LT','age',1))))]
        cases += [('range',('AND',('GE','age',35),('LE','age',50))),('empty-range',('AND',('GT','age',2**32-1),('LE','age',2**32-1))),('full',('GE','age',0)),('ne',('NE','age',35)),('double-not',('NOT',('NOT',('EQ','sex',1)))),('compound-not',('NOT',('AND',('EQ','sex',1),('GT','age',35))))]
        from epbkpir.online.session import SERVER
        self.assertTrue(SERVER.exists(),'build epbkpir/online/build.py first')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'db';prepare(root,ROWS,DATA,FIELDS,block_size=64,capacity=128)
            shapes=[];commitments=set()
            for name,expr in cases:
                r=query(root,expr,Path(t)/name)
                expected=[data for row,data in zip(ROWS,DATA) if oracle(expr,row)]
                self.assertEqual(r['status'],'ok',name)
                self.assertCountEqual([Path(f).read_bytes() for f in r['files']],expected,name)
                self.assertEqual(r['authorized_descriptions'],len(expected))
                self.assertEqual(r['m'],len(expected))
                self.assertTrue(all(s['ipbm']['m']==len(expected) for s in r['servers']))
                self.assertEqual(Path(r['descriptors_file']).stat().st_size,len(expected)*128)
                self.assertEqual(r['global_pir_batches'],int(bool(expected)))
                material=r['preprocessing']['material_commitment']
                self.assertNotIn(material,commitments);commitments.add(material)
                template=(root/'s0/template').read_text()
                self.assertFalse(any(label in template for label in ('AND','OR','NOT','EQ','LT','GT')))
                for sid in range(2):
                    for artifact in ('selected','z','audit-z','one-use-mask','one-use-occ-matrix'):
                        self.assertFalse((root/f's{sid}'/artifact).exists())
                    if not expected:continue
                    wire=(Path(r['descriptors_file']).parent/f'pir.s{sid}.keys').read_bytes()
                    header=struct.unpack_from('<9Q6I',wire);offset=96
                    self.assertEqual(header[-1],4);self.assertEqual(header[10],1)
                    for _ in range(header[4]):
                        size=struct.unpack_from('<I',wire,offset)[0];offset+=4+size
                    self.assertEqual(offset,len(wire))
                if expected:
                    shapes.append([m['bytes'] for m in r['messages'] if m['kind'] in ('dpf_keys','occ_response')])
                    self.assertTrue(all(s['backend']['masked_before_occ'] for s in r['servers']))
            self.assertTrue(all(x==shapes[0] for x in shapes))
            db=Path(t)/'overflow';prepare(db,ROWS,[bytes(64*20)]*len(ROWS),FIELDS,block_size=64,capacity=128)
            r=query(db,('GE','age',0),Path(t)/'overflow-out')
            self.assertEqual(r['status'],'PRIVATE_RETRIEVAL_FAILED');self.assertEqual(r['failure_diagnostic_local'],'capacity');self.assertEqual(r['files'],[])
            r=query(root,('GE','age',0),Path(t)/'route-out',force_route_failure=True)
            self.assertEqual(r['status'],'PRIVATE_RETRIEVAL_FAILED');self.assertEqual(r['files'],[])
            # Evidence stays in the TemporaryDirectory. Never overwrite the
            # frozen Nov14 validation artifact from a current regression test.
if __name__=='__main__':unittest.main()
