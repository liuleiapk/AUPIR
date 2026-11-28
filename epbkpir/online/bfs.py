"""GF(2) BFS-CODE: linear encoding and checksum-validated value recovery.

CCS21 Algorithms 5/6 instantiated in the paper's tagged-value XOR group.
Hashes are of public *permuted slots*, never of secret shares or values.
"""
import hashlib,math,struct
WIDTH=144
def parameters(m):
    if m<1:raise ValueError('positive sparsity required')
    eta=128+(m-1).bit_length()
    return eta,2*(eta*m-1)
def positions(slot,epoch,m):
    eta,ell=parameters(m)
    result=[];threshold=(1<<64)%ell
    for h in range(eta):
        counter=0
        while True:
            x=int.from_bytes(hashlib.sha256(struct.pack('>5Q',0x4246532d50324f31,epoch,slot,h,counter)).digest()[:8],'big');counter+=1
            if x>=threshold:result.append(x%ell);break
    return result
def encode_reference(shares,epoch,m):
    _,ell=parameters(m);out=bytearray(ell*WIDTH)
    for slot,word in enumerate(shares):
        if len(word)!=WIDTH:raise ValueError('tagged share width')
        for cell in positions(slot,epoch,m):
            for i,b in enumerate(word):out[cell*WIDTH+i]^=b
    return bytes(out)
def decode(combined,m):
    _,ell=parameters(m)
    if len(combined)!=ell*WIDTH:raise ValueError('BFS shape')
    found=set()
    for at in range(0,len(combined),WIDTH):
        cell=combined[at:at+WIDTH];payload,tag=cell[:128],cell[128:]
        if payload==bytes(128):continue
        if hashlib.sha256(payload).digest()[:16]==tag:found.add(payload)
    if len(found)!=m:raise ValueError('BFS checksum/collision/count failure')
    return sorted(found)
