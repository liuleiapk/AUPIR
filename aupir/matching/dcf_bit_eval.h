#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <cryptoTools/Crypto/AES.h>

namespace ipbm {
// Exact specialization of Kunlun's DCF MAC evaluator for keys GENERATED in
// Z_2 (not a conversion of Z_2^64 keys). Like P2FRPSO's 64-bit fast evaluator,
// expand ONLY the public input's selected child. In Z_2 both signs coincide,
// addition/subtraction are XOR, and Convert(block) is its low bit.
// No keygen/wire change, attribute-value memoization or threshold bitmap.
class DcfBitEvaluator {
    using Block=osuCrypto::block;
    unsigned depth_;
    std::array<Block,33> seeds_{};
    std::array<uint8_t,33> values_{};
    static uint8_t low_bit(Block b) {return _mm_cvtsi128_si64(b)&1;}
    static Block clear_controls() {return osuCrypto::toBlock(~uint64_t(0),~uint64_t(3));}
    static const std::array<osuCrypto::AES,4>& aes() {
        static const std::array<osuCrypto::AES,4> keys={
            osuCrypto::AES(osuCrypto::toBlock(0,0)),osuCrypto::AES(osuCrypto::toBlock(0,1)),
            osuCrypto::AES(osuCrypto::toBlock(0,2)),osuCrypto::AES(osuCrypto::toBlock(0,3))};
        return keys;
    }
public:
    template<class Values>
    DcfBitEvaluator(unsigned depth,const Block* seeds,const Values* values):depth_(depth) {
        if(depth<1||depth>32)throw std::runtime_error("DCF input width must be 1..32");
        for(unsigned i=0;i<=depth;++i){
            if(values[i]>1)throw std::runtime_error("DCF requires keys generated over Z_2");
            seeds_[i]=seeds[i];values_[i]=static_cast<uint8_t>(values[i]);
        }
    }
    // W independent real records; interleave AES rounds to hide dependency
    // latency. Key selection depends only on server-owned plaintext attributes.
    template<size_t W>
    void evaluate(const uint32_t* inputs,uint8_t* output) const {
        std::array<Block,W> state,plain,tau,value;
        std::array<uint8_t,W> sum{},previous{},keep{};
        std::array<const Block*,W> seed_keys,value_keys;
        state.fill(seeds_[0]);const auto& keys=aes();const Block clear=clear_controls();
        for(unsigned level=0;level<depth_;++level){
            for(size_t lane=0;lane<W;++lane){
                keep[lane]=(inputs[lane]>>(depth_-level-1))&1;
                previous[lane]=low_bit(state[lane]);plain[lane]=state[lane]&clear;
                seed_keys[lane]=keys[keep[lane]].mRoundKey.data();
                value_keys[lane]=keys[keep[lane]+2].mRoundKey.data();
                tau[lane]=plain[lane]^seed_keys[lane][0];
                value[lane]=plain[lane]^value_keys[lane][0];
            }
            for(unsigned round=1;round<10;++round){
                for(size_t lane=0;lane<W;++lane){
                    tau[lane]=_mm_aesenc_si128(tau[lane],seed_keys[lane][round]);
                    value[lane]=_mm_aesenc_si128(value[lane],value_keys[lane][round]);
                }
            }
            for(size_t lane=0;lane<W;++lane){
                tau[lane]=_mm_aesenclast_si128(tau[lane],seed_keys[lane][10]);tau[lane]=tau[lane]^plain[lane];
                value[lane]=_mm_aesenclast_si128(value[lane],value_keys[lane][10]);value[lane]=value[lane]^plain[lane];
                sum[lane]^=low_bit(value[lane])^(previous[lane]&values_[level]);
                const uint64_t cw_low=_mm_cvtsi128_si64(seeds_[level+1]);
                const uint64_t control=(cw_low>>(1-keep[lane]))&1;
                const Block correction=(seeds_[level+1]&clear)^osuCrypto::toBlock(0,control);
                const Block mask=_mm_set1_epi64x(-static_cast<int64_t>(previous[lane]));
                state[lane]=tau[lane]^(correction&mask);
            }
        }
        // Convert(state & ~3) has low bit zero. The original final term is
        // therefore t_last*v_last; negation has the same bit in Z_2.
        for(size_t lane=0;lane<W;++lane)output[lane]=sum[lane]^(low_bit(state[lane])&values_[depth_]);
    }
    void evaluate_all(const uint32_t* inputs,size_t n,uint8_t* output) const {
        // Optional public worker count; default remains one worker.
        const char* setting=std::getenv("IPBM_EVAL_THREADS");
        int workers=setting?std::max(1,std::atoi(setting)):1;
        const size_t batches=n/8;
        #pragma omp parallel for num_threads(workers) if(workers>1) schedule(static)
        for(size_t batch=0;batch<batches;++batch)evaluate<8>(inputs+8*batch,output+8*batch);
        size_t i=batches*8;
        for(;i<n;++i)evaluate<1>(inputs+i,output+i);
    }
};
} // namespace ipbm
