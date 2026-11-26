"""DO-only aligned encrypted object installation (paper VI-B).

Q is fixed before queries. Caller specifies supported-scope bound; a public
floor of 128 permits the existing LS profile Q+40 < ceil(1.5Q). Servers receive
the descriptors themselves as required by Algorithm 2, not descriptor shares.
"""
import hashlib,json,secrets
from pathlib import Path
from aupir.layout import build_database,LayoutKind
from .session import DESC
from .parameters import occ_parameters,CAPACITY_FLOOR
def prepare(root,rows,contents,fields,*,block_size=16384,capacity=128,version=1,object_order=None):
    start=__import__('time').perf_counter();root=Path(root)
    if not rows or len(rows)!=len(contents) or capacity<1 or block_size<1:raise ValueError('snapshot dimensions')
    if any(not 1<=s['bits']<=32 for s in fields.values()):raise ValueError('field width')
    if any(not isinstance(row[f],int) or not 0<=row[f]<(1<<s['bits']) for row in rows for f,s in fields.items()):raise ValueError('encoded attribute domain')
    Q=max(CAPACITY_FLOOR,capacity);occ=occ_parameters(Q);order=list(range(len(rows))) if object_order is None else list(object_order)
    if object_order is None:secrets.SystemRandom().shuffle(order)
    if sorted(order)!=list(range(len(rows))):raise ValueError('private object placement')
    db=build_database([contents[i] for i in order],block_size,LayoutKind.ALIGNED,0)
    # Include a zero-valued stored block for the all-empty database case only.
    image=b''.join(db.blocks) or bytes(block_size)
    desc=[None]*len(rows)
    for pos,row in enumerate(order):
        loc=db.locators[pos]
        raw=DESC.pack(1,version,secrets.token_bytes(16),loc.logical_index,loc.start_block,loc.true_length,loc.key,loc.nonce,loc.tag,loc.block_count)
        desc[row]=raw+hashlib.sha256(raw).digest()[:16]
    public={'protocol':'AUPIR-TCP-BFS-OCC-v1','N':len(rows),'fields':fields,'B':block_size,'Q':Q,'requested_capacity':capacity,'version':version,'blocks':len(image)//block_size,'data_blocks':len(db.blocks),'descriptor_bytes':128,'tagged_descriptor_bytes':144,**occ,'bfs_kappa':128,'bfs_checksum_bits':128,'capacity_policy':'fixed supported-query upper bound with public floor 128 (service choice)','dummy_policy':'virtual zero queries; no stored Q dummy blocks','storage_bytes_per_server':len(image)}
    root.mkdir(parents=True,exist_ok=False);(root/'public.json').write_text(json.dumps(public,indent=2))
    for sid in (0,1):
        d=root/f's{sid}';d.mkdir(mode=0o700)
        (d/'table').write_text('\n'.join(' '.join(str(row[f]) for f in fields) for row in rows))
        (d/'tagged-descriptors').write_bytes(b''.join(desc));(d/'database.img').write_bytes(image)
        (d/'public.json').write_text(json.dumps(public))
    public['database_preparation_seconds']=__import__('time').perf_counter()-start
    (root/'public.json').write_text(json.dumps(public,indent=2))
    return public
