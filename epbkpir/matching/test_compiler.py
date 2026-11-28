"""Mathematical checks of the final compiler, separate from cryptographic tests."""
import unittest
from .compiler import compile_query,public_template
from evaluation.final.cases import cases,oracle


def compiled_value(atoms,gates,row,fields):
    names=list(fields)
    values=[c^(a*int(row[names[col]]>gt))^(b*int(row[names[col]]<lt)) for col,bits,gt,a,lt,b,c in atoms]
    for delta,a,b in gates:
        values.append(((values[a]^delta)&(values[b]^delta))^delta)
    return values[-1]


class CompilerTests(unittest.TestCase):
    def test_rules_and_boundaries(self):
        for bits in (1,2,3,4,8,32):
            fields={'value':{'bits':bits},'sex':{'bits':1}}
            maximum=(1<<bits)-1
            points=range(1<<bits) if bits<=4 else sorted({0,1,2,34,35,36,100,maximum-1,maximum} & set(range(1<<bits))) if bits<=8 else (0,1,2,34,35,36,100,maximum-1,maximum)
            for name,expr in cases(bits):
                atoms,gates=compile_query(expr,fields)
                for x in points:
                    for sex in (0,1):
                        row={'value':x,'sex':sex}
                        self.assertEqual(compiled_value(atoms,gates,row,fields),int(oracle(expr,row)),(bits,name,row))
                self.assertTrue(all(0<=a[2]<=maximum and 0<=a[4]<=maximum for a in atoms if a[0]==0))

    def test_fusion_and_normalization(self):
        f={'value':{'bits':32},'sex':{'bits':1}}
        expr=('AND',('GE','value',35),('LE','value',100))
        atoms,gates=compile_query(expr,f)
        self.assertEqual(atoms,[(0,32,100,1,35,1,1)])
        self.assertEqual(gates,[])
        self.assertEqual(compile_query(('NOT',('NOT',expr)),f),(atoms,gates))
        a,g=compile_query(('NOT',('AND',('EQ','value',35),('EQ','sex',1))),f)
        self.assertEqual((len(a),len(g)),(2,1))
        self.assertEqual(g[0][0],1)

    def test_public_template_ignores_private_labels(self):
        f={'value':{'bits':32},'sex':{'bits':1}};templates=[]
        for op in ('AND','OR'):
            for relation in ('GT','GE','LT','LE','EQ','NE'):
                for negate in (False,True):
                    expr=(op,(relation,'value',35),('EQ','sex',1))
                    if negate:expr=('NOT',expr)
                    a,g=compile_query(expr,f);templates.append(public_template(100,2,a,g))
        self.assertEqual(len(set(templates)),1)
        for expr in (('GT','value',2**32),('LT','value',-1)):
            with self.assertRaises(ValueError):compile_query(expr,f)

if __name__=='__main__':unittest.main()
