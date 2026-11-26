"""Plaintext oracle and AND/OR/NOT-only cases for final retrieval validation."""
def oracle(expr,row):
    op=expr[0]
    if op=='NOT':return not oracle(expr[1],row)
    if op=='AND':return oracle(expr[1],row) and oracle(expr[2],row)
    if op=='OR':return oracle(expr[1],row) or oracle(expr[2],row)
    x,t=row[expr[1]],expr[2]
    return {'GT':x>t,'GE':x>=t,'LT':x<t,'LE':x<=t,'EQ':x==t,'NE':x!=t}[op]


def vector(expr,rows):return bytes(int(oracle(expr,row)) for row in rows)


def cases(bits):
    maximum=(1<<bits)-1
    thresholds=range(1<<bits) if bits<=8 else (0,1,34,35,36,100,maximum-1,maximum)
    for t in thresholds:
        for op in ('GT','GE','LT','LE','EQ','NE'):
            yield f'{op}-{t}',(op,'value',t)
    bounds=[(0,0),(0,maximum),(maximum,maximum),(maximum,0)]
    if bits>=2:bounds += [(1,2),(2,1),(1,1)]
    if bits==32:bounds += [(34,36),(35,35),(35,100)]
    for lo,hi in bounds:
        for left in ('GE','GT'):
            for right in ('LE','LT'):
                expr=('AND',(left,'value',lo),(right,'value',hi))
                yield f'range-{left}-{lo}-{right}-{hi}',expr
                yield f'not-range-{left}-{lo}-{right}-{hi}',('NOT',expr)
                yield f'reversed-order-{left}-{lo}-{right}-{hi}',('AND',expr[2],expr[1])
    for op in ('AND','OR'):
        for x in (0,1):
            for y in (0,1):
                # Different fields avoid interval fusion; same graph hides delta.
                expr=(op,('GE' if x else 'LT','value',0),('GE' if y else 'LT','sex',0))
                yield f'gate-{op}-{x}-{y}',expr
                yield f'negate-{op}-{x}-{y}',('NOT',expr)
                yield f'double-{op}-{x}-{y}',('NOT',('NOT',expr))
    expr=('OR',('AND',('EQ','sex',1),('GT','value',maximum//2)),('NOT',('LT','value',1)))
    yield 'nested',expr
    yield 'nested-negation',('NOT',expr)
    yield 'one-match',('AND',('EQ','value',0),('EQ','sex',1))


WORKLOADS={
 'sex_eq_age_gt':('AND',('EQ','sex',1),('GT','age',35)),
 'range_not_or':('OR',('AND',('GE','age',35),('LE','age',100)),('NOT',('NE','sex',0))),
}
