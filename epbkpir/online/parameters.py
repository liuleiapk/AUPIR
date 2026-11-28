"""Finite-parameter LSObvCompress profile and byte-exact block cost model.

GenRandVec with w=r is the full-band special case of the same LS algorithm.
With an independent uniform binary r-by-t submatrix, r=t+lambda gives
Pr[rank<t] <= (2**t-1)*2**(-r) < 2**(-lambda).
The protocol samples explicit matrix bits per call, not a short fixed seed.
"""
PROFILE='ls-full-band-explicit-v1'
FAILURE_BITS=40
CAPACITY_FLOOR=128  # retained service provisioning choice, NOT a paper minimum

def occ_parameters(capacity, failure_bits=FAILURE_BITS):
    if not isinstance(capacity,int) or capacity<1 or failure_bits<1:raise ValueError('OCC parameters')
    Q=capacity;H=(3*Q+1)//2;r=Q+failure_bits
    if r>=H:raise ValueError('OCC requires r<H; for lambda=40 this needs Q>=81')
    if max(H,r)>=2**32:raise ValueError('OCC serialized uint32 limit')
    return dict(occ_profile=PROFILE,occ_rows=r,occ_width=r,occ_matrix_bytes=H*((r+7)//8),
                ls_rank_parameter=failure_bits,occ_randomness='fresh explicit uniform bits per query, hidden from C until all DPF keys are sent',
                occ_rank_guarantee=f'(2^Q-1)*2^(-r) < 2^(-{failure_bits}), for fixed target columns independent of fresh matrix')

def validate_public(p):
    expected=occ_parameters(p['Q'],p['ls_rank_parameter'])
    for key,value in expected.items():
        if p.get(key)!=value:raise ValueError('inconsistent OCC parameter: '+key)
    return expected

def cost(lengths,block_size,n=256,max_hits=8,storage_limit=256*1024**2):
    """Uniform-length configurations, fixed service B, equal query weights.

    Paper VI-B costs + explicit Setup randomness delivery. Other C/S messages
    are constant in B for fixed N/template/m and are omitted from optimization.
    """
    if block_size<1:raise ValueError('block size')
    rows=[]
    for length in lengths:
        b=(length+block_size-1)//block_size;M=max(1,n*b);Q=max(CAPACITY_FLOOR,max_hits*b);H=(3*Q+1)//2
        params=occ_parameters(Q);r=params['occ_rows'];ell=(M+Q).bit_length();key_bytes=33+18*max(ell-7,0)
        upload=2*(96+H*(4+key_bytes));response=2*r*block_size;matrix=params['occ_matrix_bytes']
        storage=M*block_size+12*M+8*(H+1)
        rows.append(dict(object_length=length,block_size=block_size,object_blocks=b,database_blocks=M,
                         q=4*b,Q=Q,H=H,r=r,w=r,expansion=r/Q,domain_bits=ell,dpf_key_bytes=key_bytes,
                         dpf_upload_bytes=upload,occ_response_bytes=response,paper_cost_bytes=upload+response,
                         setup_delivery_bytes=2*matrix,online_variable_cost_bytes=upload+response+2*matrix,
                         matrix_bytes=matrix,image_bytes=M*block_size,layout_storage_bytes=storage,
                         feasible=storage<=storage_limit))
    return rows
