#include "dpf.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>
#include <random>
#include <array>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <unordered_set>
#include <vector>
#include <thread>
#include <mutex>
#include <immintrin.h>
#include <atomic>

namespace {

constexpr uint64_t KEY_MAGIC = 0x3159454b465044ULL;   // DPFKEY1
constexpr uint64_t META_MAGIC = 0x314154454d4342ULL;  // BCMETA1
constexpr uint64_t DEFAULT_PBC_SEED = 0x50424332303234ULL;
constexpr uint64_t DEFAULT_LS_SEED = 0x4c534f425643ULL;

struct KeyHeader {
    uint64_t magic, n, s, qcap, buckets, pbc_seed, ls_seed, version, domain_size;
    uint32_t log_domain, compressed, out_count, band_width, lambda_rank, reserved;
};

struct MetaHeader {
    uint64_t magic, n, s, qcap, qreal, buckets, pbc_seed, ls_seed, version;
    uint64_t domain_size, dummy_start, max_virtual_keyword;
    uint32_t compressed, out_count, band_width, lambda_rank, original_count;
    uint32_t schedule_failed, scheduler_kind;
};

struct ScheduleStats { uint64_t total_evictions = 0, max_chain = 0; };

uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

template <typename T> void write_pod(std::ostream &out, const T &v) {
    out.write(reinterpret_cast<const char *>(&v), sizeof(v));
    if (!out) throw std::runtime_error("write failed");
}

template <typename T> T read_pod(std::istream &in) {
    T v{};
    in.read(reinterpret_cast<char *>(&v), sizeof(v));
    if (!in) throw std::runtime_error("read failed");
    return v;
}

std::vector<uint64_t> parse_indices(const std::string &s) {
    std::vector<uint64_t> out;
    if (s.empty() || s == "-") return out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t end = s.find(',', pos);
        if (end == std::string::npos) end = s.size();
        out.push_back(std::stoull(s.substr(pos, end - pos)));
        pos = end + 1;
    }
    return out;
}

uint32_t ceil_log2(uint64_t x) {
    uint32_t r = 0;
    uint64_t p = 1;
    while (p < x) { p <<= 1; ++r; }
    return r;
}

// The paper reports SHA-256 with varying counters for its mPIR implementation.
// This adapter fixes the previously undocumented encoding to domain || seed ||
// index || counter, all integers big-endian, and rejects duplicate candidates by
// incrementing the counter. The exact Rust mPIR artifact was not published with
// SealPIR, so this encoding is an explicit prototype convention, not an artifact claim.
std::vector<uint64_t> candidates_seed(uint64_t index, uint64_t h, uint64_t seed) {
    std::vector<uint64_t> c;
    uint32_t counter = 0;
    while (c.size() < 3) {
        std::array<unsigned char, 36> in{};
        const char domain[] = "PBC-GENSCHEDULE";
        std::memcpy(in.data(), domain, sizeof(domain) - 1);
        for (unsigned i = 0; i < 8; ++i) in[16 + i] = static_cast<unsigned char>(seed >> (56 - 8 * i));
        for (unsigned i = 0; i < 8; ++i) in[24 + i] = static_cast<unsigned char>(index >> (56 - 8 * i));
        in[32] = static_cast<unsigned char>(counter >> 24);
        in[33] = static_cast<unsigned char>(counter >> 16);
        in[34] = static_cast<unsigned char>(counter >> 8);
        in[35] = static_cast<unsigned char>(counter);
        ++counter;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(in.data(), in.size(), digest);
        uint64_t word = 0;
        for (unsigned i = 0; i < 8; ++i) word = (word << 8) | digest[i];
        uint64_t b = word % h;
        if (std::find(c.begin(), c.end(), b) != c.end()) continue;
        c.push_back(b);
    }
    return c;
}

bool augment(size_t qi, const std::vector<uint64_t> &queries, uint64_t h, uint64_t seed,
             std::vector<int64_t> &owner, std::vector<uint8_t> &seen) {
    for (uint64_t b : candidates_seed(queries[qi], h, seed)) {
        if (seen[b]) continue;
        seen[b] = 1;
        if (owner[b] < 0 || augment(static_cast<size_t>(owner[b]), queries, h, seed, owner, seen)) {
            owner[b] = static_cast<int64_t>(qi);
            return true;
        }
    }
    return false;
}

std::vector<uint64_t> schedule_augmenting(const std::vector<uint64_t> &queries, uint64_t h, uint64_t seed) {
    std::vector<int64_t> owner(h, -1);
    for (size_t i = 0; i < queries.size(); ++i) {
        std::vector<uint8_t> seen(h, 0);
        if (!augment(i, queries, h, seed, owner, seen)) return {};
    }
    std::vector<uint64_t> assignment(queries.size(), UINT64_MAX);
    for (uint64_t b = 0; b < h; ++b) if (owner[b] >= 0) assignment[owner[b]] = b;
    return assignment;
}

// Angel et al., S&P 2018, Sec. 4.5: insert into any empty one of w
// candidates; if all are occupied, choose a candidate at random, evict, and
// recursively reinsert, subject to a maximum iteration count. Their concrete
// PBC uses w=3 and b=1.5k. The paper does not publish the iteration cap; this
// prototype records its local cap (500) separately from the paper parameters.
std::vector<uint64_t> schedule_genschedule(const std::vector<uint64_t> &queries,
                                           uint64_t h, uint64_t hash_seed,
                                           uint64_t random_seed,
                                           uint64_t max_evictions = 500,
                                           ScheduleStats *stats = nullptr) {
    std::vector<std::array<uint64_t, 3>> choices(queries.size());
    for (size_t i = 0; i < queries.size(); ++i) {
        auto c = candidates_seed(queries[i], h, hash_seed);
        choices[i] = {c[0], c[1], c[2]};
    }
    std::vector<int64_t> owner(h, -1);
    uint64_t rng = random_seed;
    for (size_t initial = 0; initial < queries.size(); ++initial) {
        size_t item = initial;
        bool placed = false;
        uint64_t chain = 0;
        for (uint64_t evictions = 0; evictions <= max_evictions; ++evictions) {
            for (uint64_t b : choices[item]) {
                if (owner[b] < 0) {
                    owner[b] = static_cast<int64_t>(item);
                    placed = true;
                    break;
                }
            }
            if (placed) break;
            rng = splitmix64(rng);
            uint64_t b = choices[item][rng % 3];
            size_t evicted = static_cast<size_t>(owner[b]);
            owner[b] = static_cast<int64_t>(item);
            item = evicted;
            ++chain;
        }
        if (stats) {
            stats->total_evictions += chain;
            stats->max_chain = std::max(stats->max_chain, chain);
        }
        if (!placed) return {};
    }
    std::vector<uint64_t> assignment(queries.size(), UINT64_MAX);
    for (uint64_t b = 0; b < h; ++b)
        if (owner[b] >= 0) assignment[static_cast<size_t>(owner[b])] = b;
    return assignment;
}

void fill_bytes(uint64_t index, uint64_t version, uint64_t offset, uint8_t *dst, size_t len) {
    if (index == 0) {
        std::memset(dst, 0, len);
        return;
    }
    size_t done = 0;
    while (done < len) {
        uint64_t word = splitmix64(index * 0xd6e8feb86659fd93ULL ^ version ^ ((offset + done) >> 3));
        size_t take = std::min<size_t>(8, len - done);
        std::memcpy(dst + done, &word, take);
        done += take;
    }
}

struct BandSample {
    uint32_t start = 0;
    std::vector<uint32_t> rows;
};

// Optional explicit public randomness for the full-band LS specialization.
// Column-major, ceil(r/8) bytes per column, low bit first. Historical seeded
// paths remain available, but the new fixed_explicit profile requires R.
std::vector<uint8_t> explicit_ls_matrix;
uint32_t explicit_ls_rows=0;
uint64_t explicit_ls_columns=0;
void load_ls_matrix(const std::string& path,uint32_t rows,uint64_t columns) {
    explicit_ls_matrix.clear();explicit_ls_rows=rows;explicit_ls_columns=columns;
    if(path.empty())return;
    const uint64_t stride=(rows+7ULL)/8;
    explicit_ls_matrix.resize(columns*stride);
    std::ifstream f(path,std::ios::binary);
    f.read(reinterpret_cast<char*>(explicit_ls_matrix.data()),explicit_ls_matrix.size());
    if(!f || f.peek()!=EOF)throw std::runtime_error("explicit OCC randomness shape");
    if(rows%8)for(uint64_t c=0;c<columns;++c)
        if(explicit_ls_matrix[c*stride+stride-1]>>(rows%8))throw std::runtime_error("OCC randomness padding");
}

BandSample sample_band(uint64_t column, uint32_t rows, uint32_t width, uint64_t seed) {
    if(!explicit_ls_matrix.empty()){
        if(rows!=explicit_ls_rows||width!=rows||column>=explicit_ls_columns)
            throw std::runtime_error("explicit full-band OCC parameters");
        BandSample out;out.start=0;const uint64_t stride=(rows+7ULL)/8;
        for(uint32_t j=0;j<rows;++j)
            if((explicit_ls_matrix[column*stride+j/8]>>(j%8))&1)out.rows.push_back(j);
        return out;
    }
    width = std::min(width, rows);
    auto digest_for = [&](const char *domain, uint32_t counter, unsigned char out[SHA256_DIGEST_LENGTH]) {
        std::array<unsigned char, 44> in{};
        std::memcpy(in.data(), domain, std::min<size_t>(23, std::strlen(domain)));
        for (unsigned i = 0; i < 8; ++i) in[24 + i] = static_cast<unsigned char>(seed >> (56 - 8 * i));
        for (unsigned i = 0; i < 8; ++i) in[32 + i] = static_cast<unsigned char>(column >> (56 - 8 * i));
        for (unsigned i = 0; i < 4; ++i) in[40 + i] = static_cast<unsigned char>(counter >> (24 - 8 * i));
        SHA256(in.data(), in.size(), out);
    };
    unsigned char digest[SHA256_DIGEST_LENGTH];
    uint32_t start = 0;
    if (rows != width) {
        // Rejection sampling avoids modulo bias.  SHA-256 is used as a PRF;
        // the domain, seed, column and counter are all separately framed.
        uint64_t bound = static_cast<uint64_t>(rows - width) + 1;
        uint64_t threshold = (uint64_t{0} - bound) % bound;
        uint32_t counter = 0;
        uint64_t word;
        do {
            digest_for("LS-BAND-START-v2", counter++, digest);
            word = 0;
            for (unsigned i = 0; i < 8; ++i) word = (word << 8) | digest[i];
        } while (word < threshold);
        start = static_cast<uint32_t>(word % bound);
    }
    BandSample out;
    out.start = start;
    for (uint32_t j = 0; j < width; ++j) {
        if ((j & 255U) == 0) digest_for("LS-BAND-BITS-v2", j / 256, digest);
        if ((digest[(j & 255U) >> 3] >> (j & 7U)) & 1U) out.rows.push_back(start + j);
    }
    return out;
}

std::vector<uint32_t> band_rows(uint64_t column, uint32_t rows, uint32_t width, uint64_t seed) {
    return sample_band(column, rows, width, seed).rows;
}

double now_seconds() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

double cpu_seconds() {
    rusage u{};
    getrusage(RUSAGE_SELF, &u);
    return u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 + u.ru_stime.tv_sec + u.ru_stime.tv_usec / 1e6;
}

long peak_rss_kib() {
    rusage u{};
    getrusage(RUSAGE_SELF, &u);
    return u.ru_maxrss;
}

long current_pss_kib() {
    std::ifstream in("/proc/self/smaps_rollup");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Pss:", 0) == 0) {
            std::istringstream row(line.substr(4));
            long value = -1;
            row >> value;
            return value;
        }
    }
    return -1;
}

void xor_masked(uint8_t *dst, const uint8_t *src, size_t len, uint8_t bit) {
    uint64_t mask = 0ULL - static_cast<uint64_t>(bit & 1U);
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t a, b;
        std::memcpy(&a, dst + i, 8);
        std::memcpy(&b, src + i, 8);
        a ^= b & mask;
        std::memcpy(dst + i, &a, 8);
    }
    for (; i < len; ++i) dst[i] ^= src[i] & static_cast<uint8_t>(mask);
}

void xor_bytes(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t a, b;
        std::memcpy(&a, dst + i, 8);
        std::memcpy(&b, src + i, 8);
        a ^= b;
        std::memcpy(dst + i, &a, 8);
    }
    for (; i < len; ++i) dst[i] ^= src[i];
}

__attribute__((target("avx2")))
void xor_bytes_avx2(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(dst + i));
        __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(dst + i), _mm256_xor_si256(a, b));
    }
    xor_bytes(dst + i, src + i, len - i);
}

__attribute__((target("avx512f")))
void xor_bytes_avx512(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        __m512i a = _mm512_loadu_si512(reinterpret_cast<const void *>(dst + i));
        __m512i b = _mm512_loadu_si512(reinterpret_cast<const void *>(src + i));
        _mm512_storeu_si512(reinterpret_cast<void *>(dst + i), _mm512_xor_si512(a, b));
    }
    xor_bytes_avx2(dst + i, src + i, len - i);
}

enum class XorKernel { Scalar, AVX2, AVX512 };

XorKernel parse_xor_kernel(const std::string &name) {
    if (name == "scalar") return XorKernel::Scalar;
    if (name == "avx2") {
        if (!__builtin_cpu_supports("avx2")) throw std::runtime_error("AVX2 unavailable");
        return XorKernel::AVX2;
    }
    if (name == "avx512") {
        if (!__builtin_cpu_supports("avx512f")) throw std::runtime_error("AVX-512 unavailable");
        return XorKernel::AVX512;
    }
    throw std::runtime_error("kernel must be scalar|avx2|avx512");
}

void xor_bytes_kernel(uint8_t *dst, const uint8_t *src, size_t len, XorKernel kernel) {
    if (kernel == XorKernel::AVX512) xor_bytes_avx512(dst, src, len);
    else if (kernel == XorKernel::AVX2) xor_bytes_avx2(dst, src, len);
    else xor_bytes(dst, src, len);
}

void write_key_file(const std::string &path, const KeyHeader &hdr,
                    const std::vector<std::vector<uint8_t>> &keys) {
    std::ofstream out(path, std::ios::binary);
    write_pod(out, hdr);
    for (const auto &key : keys) {
        uint32_t len = static_cast<uint32_t>(key.size());
        write_pod(out, len);
        out.write(reinterpret_cast<const char *>(key.data()), key.size());
    }
}

std::pair<KeyHeader, std::vector<std::vector<uint8_t>>> read_key_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    KeyHeader hdr = read_pod<KeyHeader>(in);
    if (hdr.magic != KEY_MAGIC) throw std::runtime_error("bad key-file magic");
    std::vector<std::vector<uint8_t>> keys(hdr.buckets);
    for (auto &key : keys) {
        uint32_t len = read_pod<uint32_t>(in);
        key.resize(len);
        in.read(reinterpret_cast<char *>(key.data()), len);
        if (!in) throw std::runtime_error("truncated key file");
    }
    return {hdr, std::move(keys)};
}

int prepare(int argc, char **argv) {
    if (argc < 9) throw std::runtime_error("prepare Nreal S Q indices prefix compress version [pbc_seed] [scheduler] [schedule_seed] [lambda_rank] [band_width] [ls_seed] [out_count] [hidden|revealed]");
    uint64_t n = std::stoull(argv[2]), s = std::stoull(argv[3]), qcap = std::stoull(argv[4]);
    auto original = parse_indices(argv[5]);
    std::string prefix = argv[6];
    bool compressed = std::stoi(argv[7]) != 0;
    uint64_t version = std::stoull(argv[8]);
    uint64_t seed = argc > 9 ? std::stoull(argv[9]) : DEFAULT_PBC_SEED;
    std::string scheduler = argc > 10 ? argv[10] : "genschedule";
    uint64_t schedule_seed = argc > 11 ? std::stoull(argv[11]) : splitmix64(seed ^ qcap);
    uint32_t lambda_rank = argc > 12 ? static_cast<uint32_t>(std::stoul(argv[12])) : 40;
    uint32_t width = argc > 13 ? static_cast<uint32_t>(std::stoul(argv[13]))
                               : lambda_rank + ceil_log2(qcap + 1);
    uint64_t ls_seed = argc > 14 ? std::stoull(argv[14]) : DEFAULT_LS_SEED;
    uint32_t profile_id = 0;
    if (argc > 16) {
        std::string profile = argv[16];
        profile_id = profile == "hidden" ? 1U : profile == "revealed" ? 2U : profile == "fixed" ? 3U : profile == "fixed_explicit" ? 4U : 0U;
        if (!profile_id) throw std::runtime_error("unknown cardinality profile");
        if (profile_id == 1 && qcap != 1024) throw std::runtime_error("M_HIDDEN requires Q=1024");
        if (profile_id == 2 && (qcap == 0 || qcap > 1024 || qcap % 128 != 0))
            throw std::runtime_error("M_REVEALED requires Q=128m, 1<=m<=8");
    }
    uint64_t domain_min = n + qcap + 1; // real || Q virtual dummies || reserved absent keyword.
    uint32_t log_domain = ceil_log2(domain_min);
    uint64_t domain_size = 1ULL << log_domain;

    std::vector<uint64_t> real;
    std::unordered_set<uint64_t> unique;
    for (uint64_t i : original) {
        if (i >= domain_size) throw std::runtime_error("keyword outside DPF domain");
        if (unique.insert(i).second) real.push_back(i);
    }
    if (real.size() > qcap) throw std::runtime_error("q > Q");
    std::vector<uint64_t> queries = real;
    for (uint64_t i = 0; queries.size() < qcap && i < qcap; ++i) {
        uint64_t dummy = n + i;
        if (unique.insert(dummy).second) queries.push_back(dummy);
    }
    if (queries.size() != qcap) throw std::runtime_error("insufficient distinct virtual dummy keywords");

    uint64_t h = (3 * qcap + 1) / 2;
    ScheduleStats schedule_stats;
    auto assignment = scheduler == "force_failure" ? std::vector<uint64_t>{}
        : scheduler == "augmenting" ? schedule_augmenting(queries, h, seed)
        : schedule_genschedule(queries, h, seed, schedule_seed, 500, &schedule_stats);
    bool schedule_failed = assignment.empty();
    if (schedule_failed) assignment.assign(qcap, 0);
    std::vector<uint64_t> targets(h, n + qcap); // reserved absent keyword, not a payload row.
    if (!schedule_failed)
        for (size_t i = 0; i < queries.size(); ++i) targets[assignment[i]] = queries[i];

    std::vector<std::vector<uint8_t>> k0(h), k1(h);
    size_t upload = 0;
    double start = now_seconds();
    for (uint64_t b = 0; b < h; ++b) {
        auto pair = DPF::Gen(targets[b], log_domain);
        k0[b] = std::move(pair.first);
        k1[b] = std::move(pair.second);
        upload += k0[b].size() + k1[b].size();
    }
    double keygen = now_seconds() - start;
    uint32_t c = argc > 15 ? static_cast<uint32_t>(std::stoul(argv[15]))
        : std::max<uint32_t>(static_cast<uint32_t>((105 * qcap + 99) / 100),
                             static_cast<uint32_t>(qcap + lambda_rank));
    if (compressed && c < qcap) throw std::runtime_error("LS_OUT_COUNT_LT_Q");
    if (compressed && c >= h) throw std::runtime_error("LS_NOT_BENEFICIAL: C >= H");
    width = std::min<uint32_t>(width, c);
    if(profile_id==4 && (!compressed||width!=c||c!=qcap+lambda_rank||ls_seed!=0))
        throw std::runtime_error("explicit full-band OCC profile");
    KeyHeader kh{KEY_MAGIC, n, s, qcap, h, seed, ls_seed, version, domain_size,
                 log_domain, static_cast<uint32_t>(compressed),
                 compressed ? c : static_cast<uint32_t>(h), width, lambda_rank, profile_id};
    write_key_file(prefix + ".s0.keys", kh, k0);
    write_key_file(prefix + ".s1.keys", kh, k1);

    MetaHeader mh{META_MAGIC, n, s, qcap, real.size(), h, seed, ls_seed, version,
                  domain_size, n, n + qcap - 1,
                  static_cast<uint32_t>(compressed), compressed ? c : static_cast<uint32_t>(h),
                  width, lambda_rank, static_cast<uint32_t>(original.size()),
                  static_cast<uint32_t>(schedule_failed),
                  static_cast<uint32_t>((scheduler == "augmenting" ? 1U : 0U) | (profile_id == 4 ? 0x80000000U : 0U))};
    std::ofstream meta(prefix + ".meta", std::ios::binary);
    write_pod(meta, mh);
    for (uint64_t x : queries) write_pod(meta, x);
    for (uint64_t x : assignment) write_pod(meta, x);
    for (uint64_t x : original) write_pod(meta, x);
    std::cout << "{\"phase\":\"prepare\",\"q\":" << real.size()
              << ",\"Q\":" << qcap << ",\"H\":" << h
              << ",\"dpf_key_bytes_total\":" << upload
              << ",\"keygen_seconds\":" << keygen
              << ",\"domain_size\":" << domain_size
              << ",\"dummy_start\":" << n
              << ",\"max_virtual_keyword\":" << n + qcap - 1
              << ",\"C\":" << (compressed ? c : h)
              << ",\"band_width\":" << width
              << ",\"lambda_rank\":" << lambda_rank
              << ",\"cardinality_profile_id\":" << profile_id
              << ",\"schedule_operations\":" << qcap + schedule_stats.total_evictions
              << ",\"schedule_evictions\":" << schedule_stats.total_evictions
              << ",\"schedule_failed\":" << (schedule_failed ? "true" : "false")
              << ",\"scheduler\":\"" << scheduler << "\"}\n";
    return 0;
}

struct Layout {
    std::vector<uint64_t> offsets;
    std::vector<uint32_t> indices;
    std::vector<uint8_t> base;
    std::vector<uint8_t> materialized;
};

Layout build_layout(uint64_t n, uint64_t s, uint64_t h, uint64_t seed, uint64_t version,
                    const std::string &kind, const std::string &base_path = "") {
    Layout l;
    l.offsets.assign(h + 1, 0);
    for (uint64_t i = 0; i < n; ++i)
        for (uint64_t b : candidates_seed(i, h, seed)) ++l.offsets[b + 1];
    std::partial_sum(l.offsets.begin(), l.offsets.end(), l.offsets.begin());
    l.indices.resize(3 * n);
    auto cursor = l.offsets;
    for (uint64_t i = 0; i < n; ++i)
        for (uint64_t b : candidates_seed(i, h, seed)) l.indices[cursor[b]++] = static_cast<uint32_t>(i);
    if (kind == "materialized") {
        if (s != 0 && l.indices.size() > SIZE_MAX / s) throw std::runtime_error("materialized size overflow");
        l.materialized.resize(l.indices.size() * s);
        for (size_t r = 0; r < l.indices.size(); ++r)
            fill_bytes(l.indices[r], version, 0, l.materialized.data() + r * s, s);
    } else if (kind == "indirected" || kind == "indirected_file") {
        if (s != 0 && n > SIZE_MAX / s) throw std::runtime_error("base size overflow");
        l.base.resize(n * s);
        if (kind == "indirected_file") {
            if (base_path.empty()) throw std::runtime_error("indirected_file requires database image");
            std::ifstream image(base_path, std::ios::binary);
            image.read(reinterpret_cast<char *>(l.base.data()), static_cast<std::streamsize>(l.base.size()));
            if (!image || image.peek() != std::ifstream::traits_type::eof())
                throw std::runtime_error("database image must contain exactly N*S bytes");
        } else {
            for (uint64_t i = 0; i < n; ++i) fill_bytes(i, version, 0, l.base.data() + i * s, s);
        }
    } else {
        throw std::runtime_error("layout must be materialized or indirected");
    }
    return l;
}

int server(int argc, char **argv) {
    if (argc < 8) throw std::runtime_error("server layout keyfile response stripe compress version [legacy_reference]");
    std::string kind = argv[2], key_path = argv[3], response_path = argv[4];
    uint64_t stripe = std::stoull(argv[5]);
    bool compressed = std::stoi(argv[6]) != 0;
    uint64_t version = std::stoull(argv[7]);
    auto [hdr, keys] = read_key_file(key_path);
    if (version != hdr.version) {
        std::cerr << "database/key version mismatch\n";
        return 44;
    }
    if (compressed != static_cast<bool>(hdr.compressed))
        throw std::runtime_error("server compression flag/header mismatch");
    if (compressed && (argc < 9 || std::string(argv[8]) != "legacy_reference"))
        throw std::runtime_error("one-shot compressed server is regression-only; use resident paper_faithful_optimized serve path");

    double wall0 = now_seconds(), cpu0 = cpu_seconds();
    Layout layout = build_layout(hdr.n, hdr.s, hdr.buckets, hdr.pbc_seed, version, kind);
    double build_seconds = now_seconds() - wall0;
    double select0 = now_seconds();
    std::vector<uint8_t> selection(layout.indices.size());
    for (uint64_t b = 0; b < hdr.buckets; ++b) {
        for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r)
            selection[r] = static_cast<uint8_t>(DPF::Eval(keys[b], layout.indices[r], hdr.log_domain));
    }
    double selection_seconds = now_seconds() - select0;

    uint32_t c = hdr.out_count, width = hdr.band_width;
    uint64_t out_rows = hdr.out_count;
    std::ofstream response(response_path, std::ios::binary);
    if (!response) throw std::runtime_error("cannot open response file");
    double scan0 = now_seconds(), ls_seconds = 0;
    uint64_t stripes = (hdr.s + stripe - 1) / stripe;
    for (uint64_t st = 0; st < stripes; ++st) {
        uint64_t offset = st * stripe;
        size_t len = static_cast<size_t>(std::min<uint64_t>(stripe, hdr.s - offset));
        std::vector<uint8_t> raw(hdr.buckets * len, 0);
        for (uint64_t b = 0; b < hdr.buckets; ++b) {
            uint8_t *dst = raw.data() + b * len;
            for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r) {
                const uint8_t *src = kind == "materialized"
                    ? layout.materialized.data() + r * hdr.s + offset
                    : layout.base.data() + static_cast<uint64_t>(layout.indices[r]) * hdr.s + offset;
                xor_masked(dst, src, len, selection[r]);
            }
        }
        if (compressed) {
            double ls0 = now_seconds();
            std::vector<uint8_t> comp(out_rows * len, 0);
            for (uint64_t b = 0; b < hdr.buckets; ++b) {
                const uint8_t *src = raw.data() + b * len;
                for (uint32_t row : band_rows(b, c, width, hdr.ls_seed))
                    xor_bytes(comp.data() + static_cast<uint64_t>(row) * len, src, len);
            }
            ls_seconds += now_seconds() - ls0;
            response.write(reinterpret_cast<const char *>(comp.data()), comp.size());
        } else {
            response.write(reinterpret_cast<const char *>(raw.data()), raw.size());
        }
    }
    response.close();
    double update0 = now_seconds();
    uint64_t update_bytes = 0;
    if (kind == "materialized") {
        for (size_t r = 0; r < layout.indices.size(); ++r) if (layout.indices[r] == 1) {
            fill_bytes(1, version + 1, 0, layout.materialized.data() + r * hdr.s, hdr.s);
            update_bytes += hdr.s;
        }
    } else {
        fill_bytes(1, version + 1, 0, layout.base.data() + hdr.s, hdr.s);
        update_bytes = hdr.s;
    }
    double update_seconds = now_seconds() - update0;
    double total_wall = now_seconds() - wall0;
    double total_cpu = cpu_seconds() - cpu0;
    uint64_t logical_storage = kind == "materialized"
        ? layout.materialized.size() + layout.indices.size() * sizeof(uint32_t)
        : layout.base.size() + layout.indices.size() * sizeof(uint32_t);
    std::cout << "{\"phase\":\"server\",\"layout\":\"" << kind
              << "\",\"compressed\":" << (compressed ? "true" : "false")
              << ",\"build_seconds\":" << build_seconds
              << ",\"selection_seconds\":" << selection_seconds
              << ",\"scan_plus_write_seconds\":" << now_seconds() - scan0
              << ",\"ls_seconds\":" << ls_seconds
              << ",\"wall_seconds\":" << total_wall
              << ",\"cpu_seconds\":" << total_cpu
              << ",\"peak_rss_kib\":" << peak_rss_kib()
              << ",\"current_pss_kib\":" << current_pss_kib()
              << ",\"storage_bytes\":" << logical_storage
              << ",\"scan_bytes\":" << 3 * hdr.n * hdr.s
              << ",\"update_bytes\":" << update_bytes
              << ",\"update_seconds\":" << update_seconds
              << ",\"response_bytes\":" << out_rows * hdr.s << "}\n";
    return 0;
}

int serve(int argc, char **argv) {
    if (argc < 10)
        throw std::runtime_error("serve layout N S Q stripe version pbc_seed server_id");
    std::string kind = argv[2];
    uint64_t n = std::stoull(argv[3]), s = std::stoull(argv[4]);
    uint64_t qcap = std::stoull(argv[5]), stripe = std::stoull(argv[6]);
    uint64_t version = std::stoull(argv[7]), seed = std::stoull(argv[8]);
    std::string server_id = argv[9];
    std::string implementation_mode = argc > 10 ? argv[10] : "paper_faithful_optimized";
    uint32_t thread_count = argc > 11 ? static_cast<uint32_t>(std::stoul(argv[11])) : 1;
    std::string kernel_name = argc > 12 ? argv[12] : "scalar";
    std::string encode_layout = argc > 13 ? argv[13] : "column_major";
    uint32_t expected_profile_id = 0;
    if (argc > 14) {
        std::string profile = argv[14];
        expected_profile_id = profile == "hidden" ? 1U : profile == "revealed" ? 2U : profile == "fixed" ? 3U : profile == "fixed_explicit" ? 4U : 0U;
        if (!expected_profile_id) throw std::runtime_error("unknown cardinality profile");
    }
    std::string database_image = argc > 15 ? argv[15] : "";
    if (kind == "indirected_file" && database_image.empty())
        throw std::runtime_error("serve indirected_file requires database image after profile");
    if (implementation_mode != "legacy_reference" && implementation_mode != "paper_faithful_scalar" &&
        implementation_mode != "paper_faithful_optimized")
        throw std::runtime_error("invalid server implementation mode");
    if (implementation_mode != "paper_faithful_optimized") { thread_count = 1; kernel_name = "scalar"; }
    if (encode_layout != "column_major" && encode_layout != "row_major")
        throw std::runtime_error("encode layout must be column_major|row_major");
    XorKernel kernel = parse_xor_kernel(kernel_name);
    uint64_t h = (3 * qcap + 1) / 2;
    double setup_wall0 = now_seconds(), setup_cpu0 = cpu_seconds();
    Layout layout = build_layout(n, s, h, seed, version, kind, database_image);
    double setup_wall = now_seconds() - setup_wall0;
    double setup_cpu = cpu_seconds() - setup_cpu0;
    long setup_peak = peak_rss_kib(), setup_pss = current_pss_kib();
    uint64_t storage = kind == "materialized"
        ? layout.materialized.size() + layout.indices.size() * sizeof(uint32_t)
        : layout.base.size() + layout.indices.size() * sizeof(uint32_t);
    std::cout << "{\"phase\":\"setup\",\"server_id\":\"" << server_id
              << "\",\"setup_wall_seconds\":" << setup_wall
              << ",\"setup_cpu_seconds\":" << setup_cpu
              << ",\"steady_rss_kib\":" << setup_peak
              << ",\"steady_pss_kib\":" << setup_pss
              << ",\"storage_bytes\":" << storage << "}" << std::endl;

    std::string line;
    uint64_t query_number = 0;
    while (std::getline(std::cin, line)) {
        if (line == "QUIT") break;
        std::istringstream request(line);
        std::string key_path, response_path, mask_path, matrix_path;
        request >> key_path >> response_path >> mask_path >> matrix_path;
        if (key_path.empty() || response_path.empty())
            throw std::runtime_error("serve request must be: keyfile responsefile");
        double online_wall0 = now_seconds(), online_cpu0 = cpu_seconds();
        auto [hdr, keys] = read_key_file(key_path);
        if (hdr.n != n || hdr.s != s || hdr.qcap != qcap || hdr.buckets != h ||
            hdr.pbc_seed != seed || hdr.version != version)
            throw std::runtime_error("persistent server/request parameter mismatch");
        if (expected_profile_id && hdr.reserved != expected_profile_id)
            throw std::runtime_error("cardinality profile mismatch");
        if(hdr.reserved==4 && (matrix_path.empty()||hdr.band_width!=hdr.out_count||hdr.out_count!=hdr.qcap+hdr.lambda_rank||hdr.ls_seed!=0))
            throw std::runtime_error("missing/mismatched explicit OCC Setup");
        load_ls_matrix(matrix_path,hdr.out_count,h);
        // EPBKPIR Algorithm 2, line 17: mask the H raw bucket shares BEFORE
        // LSObvCompress. The one-use mask is supplied only by this server's
        // private session process. Legacy requests without a third path retain
        // their original behavior. No mask or seed is delivered to the client.
        std::vector<uint8_t> response_mask;
        if (!mask_path.empty()) {
            response_mask.resize(h * s);
            std::ifstream mask(mask_path, std::ios::binary);
            mask.read(reinterpret_cast<char*>(response_mask.data()), response_mask.size());
            if (!mask || mask.peek() != EOF) throw std::runtime_error("response mask shape");
        }
        double schedule0 = now_seconds();
        std::vector<std::vector<uint32_t>> column_targets, row_sources;
        uint64_t matrix_nonzeros = 0;
        if (hdr.compressed && implementation_mode != "legacy_reference") {
            column_targets.resize(h);
            row_sources.resize(hdr.out_count);
            for (uint32_t b = 0; b < h; ++b) {
                column_targets[b] = band_rows(b, hdr.out_count, hdr.band_width, hdr.ls_seed);
                matrix_nonzeros += column_targets[b].size();
                for (uint32_t row : column_targets[b]) row_sources[row].push_back(b);
            }
        }
        double schedule_build_seconds = now_seconds() - schedule0;
        double select0 = now_seconds();
        std::vector<uint8_t> selection(layout.indices.size());
        for (uint64_t b = 0; b < h; ++b)
            for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r)
                selection[r] = static_cast<uint8_t>(DPF::Eval(keys[b], layout.indices[r], hdr.log_domain));
        double selection_seconds = now_seconds() - select0;

        std::ofstream response(response_path, std::ios::binary);
        if (!response) throw std::runtime_error("cannot open persistent response file");
        double scan_seconds = 0, ls_seconds = 0, write_seconds = 0, response_mask_seconds = 0;
        std::vector<uint8_t> raw, comp;
        uint64_t stripes = (s + stripe - 1) / stripe;
        for (uint64_t st = 0; st < stripes; ++st) {
            uint64_t offset = st * stripe;
            size_t len = static_cast<size_t>(std::min<uint64_t>(stripe, s - offset));
            double scan0 = now_seconds();
            raw.assign(h * len, 0);
            for (uint64_t b = 0; b < h; ++b) {
                uint8_t *dst = raw.data() + b * len;
                for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r) {
                    const uint8_t *src = kind == "materialized"
                        ? layout.materialized.data() + r * s + offset
                        : layout.base.data() + static_cast<uint64_t>(layout.indices[r]) * s + offset;
                    xor_masked(dst, src, len, selection[r]);
                }
            }
            scan_seconds += now_seconds() - scan0;
            double mask0 = now_seconds();
            if (!response_mask.empty())
                for (uint64_t b = 0; b < h; ++b)
                    xor_bytes(raw.data() + b * len, response_mask.data() + b * s + offset, len);
            response_mask_seconds += now_seconds() - mask0;
            const uint8_t *out_data = raw.data();
            size_t out_size = raw.size();
            if (hdr.compressed) {
                double ls0 = now_seconds();
                comp.assign(static_cast<uint64_t>(hdr.out_count) * len, 0);
                if (implementation_mode == "legacy_reference") {
                    for (uint64_t b = 0; b < h; ++b) {
                        const uint8_t *src = raw.data() + b * len;
                        auto targets = band_rows(b, hdr.out_count, hdr.band_width, hdr.ls_seed);
                        if (st == 0) matrix_nonzeros += targets.size();
                        for (uint32_t row : targets)
                            xor_bytes(comp.data() + static_cast<uint64_t>(row) * len, src, len);
                    }
                } else if (implementation_mode == "paper_faithful_scalar") {
                    for (uint64_t b = 0; b < h; ++b) {
                        const uint8_t *src = raw.data() + b * len;
                        for (uint32_t row : column_targets[b])
                            xor_bytes(comp.data() + static_cast<uint64_t>(row) * len, src, len);
                    }
                } else if (encode_layout == "row_major") {
                    std::vector<std::thread> workers;
                    for (uint32_t tid = 0; tid < thread_count; ++tid) workers.emplace_back([&, tid] {
                        for (uint32_t row = tid; row < hdr.out_count; row += thread_count) {
                            uint8_t *dst = comp.data() + static_cast<uint64_t>(row) * len;
                            for (uint32_t b : row_sources[row])
                                xor_bytes_kernel(dst, raw.data() + static_cast<uint64_t>(b) * len, len, kernel);
                        }
                    });
                    for (auto &worker : workers) worker.join();
                } else {
                    std::vector<std::thread> workers;
                    for (uint32_t tid = 0; tid < thread_count; ++tid) workers.emplace_back([&, tid] {
                        size_t begin = len * tid / thread_count, end = len * (tid + 1) / thread_count;
                        for (uint32_t b = 0; b < h; ++b) {
                            const uint8_t *src = raw.data() + static_cast<uint64_t>(b) * len + begin;
                            for (uint32_t row : column_targets[b])
                                xor_bytes_kernel(comp.data() + static_cast<uint64_t>(row) * len + begin,
                                                 src, end - begin, kernel);
                        }
                    });
                    for (auto &worker : workers) worker.join();
                }
                ls_seconds += now_seconds() - ls0;
                out_data = comp.data();
                out_size = comp.size();
            }
            double write0 = now_seconds();
            response.write(reinterpret_cast<const char *>(out_data), out_size);
            if (!response) throw std::runtime_error("persistent response write failed");
            write_seconds += now_seconds() - write0;
        }
        response.close();
        double online_wall = now_seconds() - online_wall0;
        double online_cpu = cpu_seconds() - online_cpu0;
        long peak = peak_rss_kib(), pss = current_pss_kib();
        std::ifstream key_size_file(key_path, std::ios::binary | std::ios::ate);
        uint64_t request_bytes = static_cast<uint64_t>(key_size_file.tellg());
        uint64_t logical_bucket_incidences = layout.indices.size();
        uint64_t base_records_read = logical_bucket_incidences;
        uint64_t physical_payload_bytes_read = base_records_read * s;
        uint64_t dpf_eval_calls = logical_bucket_incidences;
        uint64_t dpf_stop = hdr.log_domain >= 7 ? hdr.log_domain - 7 : 0;
        uint64_t dpf_prg_expansions = dpf_eval_calls * 2 * dpf_stop;
        std::cout << "{\"phase\":\"online\",\"server_id\":\"" << server_id
                  << "\",\"implementation_mode\":\"" << implementation_mode
                  << "\",\"thread_count\":" << thread_count
                  << ",\"kernel\":\"" << kernel_name
                  << "\",\"encode_layout\":\"" << encode_layout
                  << "\",\"schedule_build_seconds\":" << schedule_build_seconds
                  << ",\"query_number\":" << query_number++
                  << ",\"selection_seconds\":" << selection_seconds
                  << ",\"scan_seconds\":" << scan_seconds
                  << ",\"database_passes\":1"
                  << ",\"base_records_read\":" << base_records_read
                  << ",\"physical_payload_bytes_read\":" << physical_payload_bytes_read
                  << ",\"logical_bucket_incidences\":" << logical_bucket_incidences
                  << ",\"logical_payload_bytes_processed\":" << logical_bucket_incidences * s
                  << ",\"bucket_pir_instances\":" << h
                  << ",\"dpf_eval_calls\":" << dpf_eval_calls
                  << ",\"dpf_prg_expansions\":" << dpf_prg_expansions
                  << ",\"xor_payload_bytes\":" << logical_bucket_incidences * s
                  << ",\"ls_encode_seconds\":" << ls_seconds
                  << ",\"masked_before_occ\":" << (!mask_path.empty() ? "true" : "false")
                  << ",\"response_mask_seconds\":" << response_mask_seconds
                  << ",\"matrix_nonzero_count\":" << matrix_nonzeros
                  << ",\"explicit_matrix_bytes\":" << explicit_ls_matrix.size()
                  << ",\"total_logical_xor_bytes\":" << matrix_nonzeros * s
                  << ",\"response_write_seconds\":" << write_seconds
                  << ",\"online_wall_seconds\":" << online_wall
                  << ",\"online_cpu_seconds\":" << online_cpu
                  << ",\"steady_pss_kib\":" << pss
                  << ",\"peak_rss_kib\":" << peak
                  << ",\"incremental_peak_rss_kib\":" << std::max<long>(0, peak - setup_peak)
                  << ",\"logical_scan_bytes\":" << 3 * n * s
                  << ",\"request_bytes\":" << request_bytes
                  << ",\"response_bytes\":" << static_cast<uint64_t>(hdr.out_count) * s
                  << ",\"dpf_eval_count\":" << 3 * n << "}" << std::endl;
    }
    return 0;
}

// Experimental ablation only.  Both modes use the same DPF implementation,
// synthetic database, query set, domain, and byte-wise recovery check.  LS is
// deliberately absent so the counters isolate PBC from Q independent scans.
int pir_ablation(int argc, char **argv) {
    if (argc < 8)
        throw std::runtime_error("pir_ablation naive_q_scan|pbc N S Q version seed [stripe]");
    const std::string mode = argv[2];
    const uint64_t n = std::stoull(argv[3]), s = std::stoull(argv[4]);
    const uint64_t qcap = std::stoull(argv[5]), version = std::stoull(argv[6]);
    const uint64_t seed = std::stoull(argv[7]);
    const uint64_t stripe = argc > 8 ? std::stoull(argv[8]) : 65536;
    if (mode != "naive_q_scan" && mode != "pbc")
        throw std::runtime_error("pir_ablation mode must be naive_q_scan|pbc");
    if (!n || !s || !qcap || !stripe) throw std::runtime_error("pir_ablation zero parameter");

    const uint64_t domain_min = n + qcap + 1;
    const uint32_t log_domain = ceil_log2(domain_min);
    const uint64_t real_queries = std::min(n, qcap);
    std::vector<uint64_t> queries(qcap);
    for (uint64_t i = 0; i < real_queries; ++i) queries[i] = i;
    for (uint64_t i = real_queries; i < qcap; ++i) queries[i] = n + i;

    const uint64_t h = (3 * qcap + 1) / 2;
    std::vector<uint64_t> assignment;
    std::vector<uint64_t> targets;
    ScheduleStats schedule_stats;
    double schedule0 = now_seconds();
    if (mode == "pbc") {
        assignment = schedule_genschedule(queries, h, seed, splitmix64(seed ^ qcap), 500,
                                          &schedule_stats);
        if (assignment.empty()) throw std::runtime_error("pir_ablation GenSchedule failure");
        targets.assign(h, n + qcap);
        for (uint64_t i = 0; i < qcap; ++i) targets[assignment[i]] = queries[i];
    } else {
        targets = queries;
        assignment.resize(qcap);
        std::iota(assignment.begin(), assignment.end(), uint64_t{0});
    }
    const double schedule_seconds = now_seconds() - schedule0;
    const uint64_t output_rows = targets.size();

    std::vector<std::vector<uint8_t>> keys0(output_rows), keys1(output_rows);
    uint64_t request_bytes_total = 0;
    double keygen0 = now_seconds();
    for (uint64_t r = 0; r < output_rows; ++r) {
        auto pair = DPF::Gen(targets[r], log_domain);
        keys0[r] = std::move(pair.first);
        keys1[r] = std::move(pair.second);
        request_bytes_total += keys0[r].size() + keys1[r].size();
    }
    const double keygen_seconds = now_seconds() - keygen0;

    if (s > SIZE_MAX / n) throw std::runtime_error("pir_ablation database size overflow");
    std::vector<uint8_t> base(n * s);
    for (uint64_t i = 0; i < n; ++i) fill_bytes(i, version, 0, base.data() + i * s, s);

    Layout layout;
    if (mode == "pbc") layout = build_layout(n, 1, h, seed, version, "indirected");
    const uint64_t incidences = mode == "pbc" ? layout.indices.size() : n * qcap;
    const uint64_t eval_calls = incidences;
    std::vector<uint8_t> select0(eval_calls), select1(eval_calls);
    double eval0 = now_seconds();
    if (mode == "pbc") {
        for (uint64_t b = 0; b < h; ++b)
            for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r) {
                select0[r] = static_cast<uint8_t>(DPF::Eval(keys0[b], layout.indices[r], log_domain));
                select1[r] = static_cast<uint8_t>(DPF::Eval(keys1[b], layout.indices[r], log_domain));
            }
    } else {
        for (uint64_t q = 0; q < qcap; ++q)
            for (uint64_t i = 0; i < n; ++i) {
                const uint64_t at = q * n + i;
                select0[at] = static_cast<uint8_t>(DPF::Eval(keys0[q], i, log_domain));
                select1[at] = static_cast<uint8_t>(DPF::Eval(keys1[q], i, log_domain));
            }
    }
    const double dpf_eval_seconds = now_seconds() - eval0;

    bool correct = true;
    double scan0 = now_seconds(), cpu0 = cpu_seconds();
    for (uint64_t off = 0; off < s; off += stripe) {
        const size_t len = static_cast<size_t>(std::min(stripe, s - off));
        std::vector<uint8_t> out0(output_rows * len), out1(output_rows * len);
        if (mode == "pbc") {
            for (uint64_t b = 0; b < h; ++b)
                for (uint64_t r = layout.offsets[b]; r < layout.offsets[b + 1]; ++r) {
                    const uint8_t *src = base.data() + static_cast<uint64_t>(layout.indices[r]) * s + off;
                    xor_masked(out0.data() + b * len, src, len, select0[r]);
                    xor_masked(out1.data() + b * len, src, len, select1[r]);
                }
        } else {
            for (uint64_t q = 0; q < qcap; ++q)
                for (uint64_t i = 0; i < n; ++i) {
                    const uint8_t *src = base.data() + i * s + off;
                    const uint64_t at = q * n + i;
                    xor_masked(out0.data() + q * len, src, len, select0[at]);
                    xor_masked(out1.data() + q * len, src, len, select1[at]);
                }
        }
        for (uint64_t q = 0; q < qcap && correct; ++q) {
            const uint64_t row = assignment[q];
            const uint8_t *expected = q < real_queries ? base.data() + q * s + off : nullptr;
            for (size_t j = 0; j < len; ++j) {
                const uint8_t got = out0[row * len + j] ^ out1[row * len + j];
                if (got != (expected ? expected[j] : 0)) { correct = false; break; }
            }
        }
    }
    const double scan_seconds = now_seconds() - scan0;
    const double scan_cpu_seconds = cpu_seconds() - cpu0;
    const uint64_t logical_bytes = incidences * s;
    const uint64_t dpf_stop = log_domain >= 7 ? log_domain - 7 : 0;
    std::cout << "{\"phase\":\"pir_ablation\",\"mode\":\"" << mode
              << "\",\"N\":" << n << ",\"S\":" << s << ",\"Q\":" << qcap
              << ",\"H\":" << (mode == "pbc" ? h : qcap)
              << ",\"real_queries\":" << real_queries
              << ",\"database_passes\":" << (mode == "pbc" ? 1 : qcap)
              << ",\"base_records_read\":" << incidences
              << ",\"physical_payload_bytes_read\":" << logical_bytes
              << ",\"logical_bucket_incidences\":" << incidences
              << ",\"logical_payload_bytes_processed\":" << logical_bytes
              << ",\"bucket_pir_instances\":" << output_rows
              << ",\"dpf_eval_calls\":" << eval_calls
              << ",\"dpf_prg_expansions\":" << eval_calls * 2 * dpf_stop
              << ",\"xor_payload_bytes\":" << logical_bytes
              << ",\"schedule_operations\":" << qcap + schedule_stats.total_evictions
              << ",\"schedule_seconds\":" << schedule_seconds
              << ",\"dpf_keygen_seconds\":" << keygen_seconds
              << ",\"dpf_eval_seconds\":" << dpf_eval_seconds
              << ",\"scan_wall_seconds\":" << scan_seconds
              << ",\"scan_cpu_seconds\":" << scan_cpu_seconds
              << ",\"request_bytes_two_servers\":" << request_bytes_total
              << ",\"response_bytes_per_server\":" << output_rows * s
              << ",\"peak_rss_kib\":" << peak_rss_kib()
              << ",\"correct\":" << (correct ? "true" : "false") << "}\n";
    return correct ? 0 : 3;
}

int schedule_trials(int argc, char **argv) {
    if (argc < 6)
        throw std::runtime_error("schedule_trials Q trials genschedule|augmenting seed");
    uint64_t qcap = std::stoull(argv[2]), trials = std::stoull(argv[3]);
    std::string scheduler = argv[4];
    uint64_t master_seed = std::stoull(argv[5]);
    uint32_t thread_count = argc > 6 ? static_cast<uint32_t>(std::stoul(argv[6]))
                                     : std::max(1U, std::thread::hardware_concurrency() / 2);
    thread_count = std::min<uint32_t>(thread_count, static_cast<uint32_t>(trials));
    uint64_t h = (3 * qcap + 1) / 2;
    std::vector<uint64_t> evictions(trials), max_chains(trials);
    std::vector<uint8_t> succeeded(trials);
    double wall0 = now_seconds();
    auto worker = [&](uint32_t tid) {
        for (uint64_t t = tid; t < trials; t += thread_count) {
            uint64_t state = splitmix64(master_seed ^ t);
            std::vector<uint64_t> queries;
            queries.reserve(qcap);
            std::unordered_set<uint64_t> used;
            while (queries.size() < qcap) {
                state = splitmix64(state);
                uint64_t x = state;
                if (used.insert(x).second) queries.push_back(x);
            }
            uint64_t hash_seed = splitmix64(master_seed + 2 * t);
            uint64_t random_seed = splitmix64(master_seed + 2 * t + 1);
            ScheduleStats st;
            auto assignment = scheduler == "augmenting"
                ? schedule_augmenting(queries, h, hash_seed)
                : schedule_genschedule(queries, h, hash_seed, random_seed, 500, &st);
            succeeded[t] = !assignment.empty();
            evictions[t] = st.total_evictions;
            max_chains[t] = st.max_chain;
        }
    };
    std::vector<std::thread> pool;
    for (uint32_t t = 0; t < thread_count; ++t) pool.emplace_back(worker, t);
    for (auto &t : pool) t.join();
    uint64_t success = std::accumulate(succeeded.begin(), succeeded.end(), uint64_t{0});
    uint64_t failure = trials - success;
    auto sorted = evictions;
    std::sort(sorted.begin(), sorted.end());
    auto quantile = [&](double p) { return sorted[std::min<uint64_t>(trials - 1, static_cast<uint64_t>(std::ceil(p * trials)) - 1)]; };
    long double sum = std::accumulate(evictions.begin(), evictions.end(), static_cast<long double>(0));
    uint64_t maximum_chain = *std::max_element(max_chains.begin(), max_chains.end());
    uint64_t maximum_total = *std::max_element(evictions.begin(), evictions.end());
    std::cout << "{\"phase\":\"schedule_trials\",\"scheduler\":\"" << scheduler
              << "\",\"Q\":" << qcap << ",\"H\":" << h
              << ",\"trials\":" << trials << ",\"success\":" << success
              << ",\"failure\":" << failure
              << ",\"threads\":" << thread_count
              << ",\"evictions_mean\":" << static_cast<double>(sum / trials)
              << ",\"evictions_p50\":" << quantile(0.50)
              << ",\"evictions_p95\":" << quantile(0.95)
              << ",\"evictions_p99\":" << quantile(0.99)
              << ",\"evictions_max_total\":" << maximum_total
              << ",\"evictions_max_chain\":" << maximum_chain
              << ",\"wall_seconds\":" << now_seconds() - wall0 << "}\n";
    return 0;
}

struct ScalarSolveResult {
    bool full_rank = false, residual_ok = false;
    std::vector<uint64_t> values;
};

ScalarSolveResult solve_ls_scalar(const std::vector<uint64_t> &selected, uint32_t rows,
                                  uint32_t width, uint64_t seed,
                                  const std::vector<uint64_t> &input_rhs) {
    uint32_t cols = static_cast<uint32_t>(selected.size());
    uint32_t words = (cols + 63) / 64;
    std::vector<std::vector<uint64_t>> a(rows, std::vector<uint64_t>(words));
    for (uint32_t col = 0; col < cols; ++col)
        for (uint32_t r : band_rows(selected[col], rows, width, seed))
            a[r][col >> 6] ^= 1ULL << (col & 63);
    auto original = a;
    auto rhs = input_rhs;
    std::vector<uint32_t> piv(cols, UINT32_MAX);
    uint32_t rank = 0;
    for (uint32_t col = 0; col < cols; ++col) {
        uint32_t p = rank;
        while (p < rows && ((a[p][col >> 6] >> (col & 63)) & 1ULL) == 0) ++p;
        if (p == rows) return {};
        std::swap(a[p], a[rank]);
        std::swap(rhs[p], rhs[rank]);
        piv[col] = rank;
        for (uint32_t r = rank + 1; r < rows; ++r) {
            if (((a[r][col >> 6] >> (col & 63)) & 1ULL) == 0) continue;
            for (uint32_t w = col >> 6; w < words; ++w) a[r][w] ^= a[rank][w];
            rhs[r] ^= rhs[rank];
        }
        ++rank;
    }
    ScalarSolveResult result;
    result.full_rank = true;
    result.values.assign(cols, 0);
    for (int64_t col = static_cast<int64_t>(cols) - 1; col >= 0; --col) {
        uint64_t v = rhs[piv[col]];
        for (uint32_t j = static_cast<uint32_t>(col + 1); j < cols; ++j)
            if ((a[piv[col]][j >> 6] >> (j & 63)) & 1ULL) v ^= result.values[j];
        result.values[col] = v;
    }
    result.residual_ok = true;
    for (uint32_t r = 0; r < rows; ++r) {
        uint64_t v = 0;
        for (uint32_t col = 0; col < cols; ++col)
            if ((original[r][col >> 6] >> (col & 63)) & 1ULL) v ^= result.values[col];
        if (v != input_rhs[r]) { result.residual_ok = false; break; }
    }
    return result;
}

std::vector<uint64_t> ls_encode_scalar(const std::vector<uint64_t> &selected,
                                       const std::vector<uint64_t> &values,
                                       uint32_t rows, uint32_t width, uint64_t seed) {
    std::vector<uint64_t> out(rows);
    for (size_t col = 0; col < selected.size(); ++col)
        for (uint32_t r : band_rows(selected[col], rows, width, seed)) out[r] ^= values[col];
    return out;
}

bool ls_full_column_rank(uint32_t cols, uint32_t rows, uint32_t width, uint64_t seed) {
    uint32_t words = (cols + 63) / 64;
    std::vector<uint64_t> a(static_cast<uint64_t>(rows) * words, 0);
    for (uint32_t col = 0; col < cols; ++col)
        for (uint32_t r : band_rows(col, rows, width, seed))
            a[static_cast<uint64_t>(r) * words + (col >> 6)] ^= 1ULL << (col & 63);
    uint32_t rank = 0;
    for (uint32_t col = 0; col < cols; ++col) {
        uint32_t p = rank;
        while (p < rows && ((a[static_cast<uint64_t>(p) * words + (col >> 6)]
                              >> (col & 63)) & 1ULL) == 0) ++p;
        if (p == rows) return false;
        if (p != rank)
            for (uint32_t w = col >> 6; w < words; ++w)
                std::swap(a[static_cast<uint64_t>(p) * words + w],
                          a[static_cast<uint64_t>(rank) * words + w]);
        for (uint32_t r = rank + 1; r < rows; ++r) {
            if (((a[static_cast<uint64_t>(r) * words + (col >> 6)] >> (col & 63)) & 1ULL) == 0)
                continue;
            for (uint32_t w = col >> 6; w < words; ++w)
                a[static_cast<uint64_t>(r) * words + w] ^=
                    a[static_cast<uint64_t>(rank) * words + w];
        }
        ++rank;
    }
    return true;
}

int ls_rank_trials(int argc, char **argv) {
    if (argc < 7) throw std::runtime_error("ls_rank_trials Q C trials band_width seed [threads]");
    uint32_t qcap = static_cast<uint32_t>(std::stoul(argv[2]));
    uint32_t rows = static_cast<uint32_t>(std::stoul(argv[3]));
    uint64_t trials = std::stoull(argv[4]);
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[5]));
    uint64_t master_seed = std::stoull(argv[6]);
    uint32_t thread_count = argc > 7 ? static_cast<uint32_t>(std::stoul(argv[7]))
        : std::max(1U, std::thread::hardware_concurrency() / 2);
    if (qcap == 0 || rows < qcap || width == 0 || width > rows || trials == 0)
        throw std::runtime_error("invalid LS rank-trial parameters");
    thread_count = std::min<uint32_t>(thread_count, static_cast<uint32_t>(trials));
    std::vector<uint64_t> failures(thread_count, 0);
    double wall0 = now_seconds(), cpu0 = cpu_seconds();
    auto worker = [&](uint32_t tid) {
        for (uint64_t t = tid; t < trials; t += thread_count) {
            uint64_t matrix_seed = splitmix64(master_seed ^ (t * 0x9e3779b97f4a7c15ULL));
            if (!ls_full_column_rank(qcap, rows, width, matrix_seed)) ++failures[tid];
        }
    };
    std::vector<std::thread> pool;
    for (uint32_t tid = 0; tid < thread_count; ++tid) pool.emplace_back(worker, tid);
    for (auto &thread : pool) thread.join();
    uint64_t rank_failure = std::accumulate(failures.begin(), failures.end(), uint64_t{0});
    double wall = now_seconds() - wall0;
    std::cout << "{\"phase\":\"ls_rank_trials\",\"Q\":" << qcap
              << ",\"H\":" << (3 * qcap + 1) / 2 << ",\"C\":" << rows
              << ",\"band_width\":" << width << ",\"trials\":" << trials
              << ",\"rank_failure\":" << rank_failure << ",\"threads\":" << thread_count
              << ",\"rank_plan_wall_seconds\":" << wall
              << ",\"rank_plan_cpu_seconds\":" << cpu_seconds() - cpu0
              << ",\"matrix_distribution\":\"SHA256_PRF_COLUMN_BAND_GF2_v2\"}\n";
    return 0;
}

int ls_distribution_audit(int argc, char **argv) {
    if (argc < 6) throw std::runtime_error("ls_distribution_audit C band_width samples seed");
    uint32_t rows = static_cast<uint32_t>(std::stoul(argv[2]));
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[3]));
    uint64_t samples = std::stoull(argv[4]), seed = std::stoull(argv[5]);
    if (rows == 0 || width == 0 || width > rows || samples == 0)
        throw std::runtime_error("invalid LS distribution-audit parameters");
    uint32_t starts = rows - width + 1;
    std::vector<uint64_t> counts(starts, 0);
    uint64_t ones = 0, all_zero = 0;
    for (uint64_t i = 0; i < samples; ++i) {
        BandSample band = sample_band(i, rows, width, splitmix64(seed ^ i));
        ++counts[band.start];
        ones += band.rows.size();
        all_zero += band.rows.empty();
        for (uint32_t r : band.rows)
            if (r < band.start || r >= band.start + width)
                throw std::runtime_error("LS bit escaped its band");
    }
    auto mm = std::minmax_element(counts.begin(), counts.end());
    std::cout << "{\"phase\":\"ls_distribution_audit\",\"C\":" << rows
              << ",\"band_width\":" << width << ",\"samples\":" << samples
              << ",\"start_domain\":" << starts << ",\"start_min_count\":" << *mm.first
              << ",\"start_max_count\":" << *mm.second << ",\"ones_fraction\":"
              << static_cast<double>(ones) / (samples * width)
              << ",\"all_zero_bands\":" << all_zero
              << ",\"start_sampling\":\"UINT64_REJECTION_UNBIASED\""
              << ",\"start_domain_tag\":\"LS-BAND-START-v2\""
              << ",\"bits_domain_tag\":\"LS-BAND-BITS-v2\"}\n";
    return 0;
}

int ls_trials(int argc, char **argv) {
    if (argc < 7) throw std::runtime_error("ls_trials Q trials lambda_rank band_width seed");
    uint64_t qcap = std::stoull(argv[2]), trials = std::stoull(argv[3]);
    uint32_t lambda_rank = static_cast<uint32_t>(std::stoul(argv[4]));
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[5]));
    uint64_t master_seed = std::stoull(argv[6]);
    uint64_t h = (3 * qcap + 1) / 2;
    uint32_t c = std::max<uint32_t>(static_cast<uint32_t>((105 * qcap + 99) / 100),
                                    static_cast<uint32_t>(qcap + lambda_rank));
    if (c >= h) {
        std::cout << "{\"phase\":\"ls_trials\",\"Q\":" << qcap << ",\"H\":" << h
                  << ",\"C\":" << c << ",\"lambda_rank\":" << lambda_rank
                  << ",\"band_width\":" << width << ",\"status\":\"LS_NOT_BENEFICIAL\"}\n";
        return 0;
    }
    uint64_t schedule_fail = 0, rank_fail = 0, decode_fail = 0;
    uint64_t tamper_undetected = 0, seed_mismatch_undetected = 0;
    double wall0 = now_seconds(), solve_seconds = 0, encode_seconds = 0;
    for (uint64_t t = 0; t < trials; ++t) {
        uint64_t state = splitmix64(master_seed ^ t);
        std::vector<uint64_t> queries(qcap);
        std::unordered_set<uint64_t> used;
        for (uint64_t &x : queries) {
            do { state = splitmix64(state); x = state; } while (!used.insert(x).second);
        }
        auto assignment = schedule_genschedule(queries, h, splitmix64(master_seed + 2*t),
                                               splitmix64(master_seed + 2*t + 1));
        if (assignment.empty()) { ++schedule_fail; continue; }
        uint64_t matrix_seed = splitmix64(master_seed ^ (t * 0x9e3779b97f4a7c15ULL));
        std::vector<uint64_t> values(qcap);
        if (t & 1ULL) for (uint64_t &v : values) { state = splitmix64(state); v = state; }
        double e0 = now_seconds();
        auto encoded = ls_encode_scalar(assignment, values, c, width, matrix_seed);
        encode_seconds += now_seconds() - e0;
        double s0 = now_seconds();
        auto solved = solve_ls_scalar(assignment, c, width, matrix_seed, encoded);
        solve_seconds += now_seconds() - s0;
        if (!solved.full_rank) { ++rank_fail; continue; }
        if (!solved.residual_ok || solved.values != values) ++decode_fail;
        auto tampered = encoded;
        tampered[t % c] ^= 1ULL << (t & 63);
        auto tamper_solved = solve_ls_scalar(assignment, c, width, matrix_seed, tampered);
        if (tamper_solved.full_rank && tamper_solved.residual_ok && tamper_solved.values == values)
            ++tamper_undetected;
        auto mismatch = solve_ls_scalar(assignment, c, width, matrix_seed ^ 1ULL, encoded);
        if ((t & 1ULL) && mismatch.full_rank && mismatch.residual_ok && mismatch.values == values)
            ++seed_mismatch_undetected;
    }
    std::cout << "{\"phase\":\"ls_trials\",\"Q\":" << qcap << ",\"H\":" << h
              << ",\"C\":" << c << ",\"lambda_rank\":" << lambda_rank
              << ",\"band_width\":" << width << ",\"trials\":" << trials
              << ",\"schedule_failure\":" << schedule_fail
              << ",\"rank_failure\":" << rank_fail << ",\"decode_failure\":" << decode_fail
              << ",\"tamper_undetected\":" << tamper_undetected
              << ",\"seed_mismatch_undetected\":" << seed_mismatch_undetected
              << ",\"scalar_encode_seconds\":" << encode_seconds
              << ",\"scalar_decode_seconds\":" << solve_seconds
              << ",\"wall_seconds\":" << now_seconds() - wall0
              << ",\"status\":\"PASS_EXPERIMENTAL_ONLY\"}\n";
    return 0;
}

struct Meta {
    MetaHeader h;
    std::vector<uint64_t> queries, assignment, original;
};

Meta read_meta(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    Meta m;
    m.h = read_pod<MetaHeader>(in);
    if (m.h.magic != META_MAGIC) throw std::runtime_error("bad metadata magic");
    m.queries.resize(m.h.qcap);
    m.assignment.resize(m.h.qcap);
    m.original.resize(m.h.original_count);
    for (auto &x : m.queries) x = read_pod<uint64_t>(in);
    for (auto &x : m.assignment) x = read_pod<uint64_t>(in);
    for (auto &x : m.original) x = read_pod<uint64_t>(in);
    return m;
}

struct LSOp { uint32_t dst, src; bool swap; };
struct LSPlan {
    bool full_rank = false;
    uint32_t rows = 0, cols = 0;
    std::vector<uint32_t> piv;
    std::vector<LSOp> forward;
    std::vector<std::vector<uint32_t>> back_dependencies;
};

LSPlan build_ls_plan(const Meta &m) {
    LSPlan plan;
    plan.rows = m.h.out_count;
    plan.cols = static_cast<uint32_t>(m.h.qcap);
    uint32_t words = (plan.cols + 63) / 64;
    std::vector<std::vector<uint64_t>> a(plan.rows, std::vector<uint64_t>(words));
    for (uint32_t col = 0; col < plan.cols; ++col)
        for (uint32_t r : band_rows(m.assignment[col], plan.rows, m.h.band_width, m.h.ls_seed))
            a[r][col >> 6] ^= 1ULL << (col & 63);
    plan.piv.assign(plan.cols, UINT32_MAX);
    uint32_t rank = 0;
    for (uint32_t col = 0; col < plan.cols; ++col) {
        uint32_t p = rank;
        while (p < plan.rows && ((a[p][col >> 6] >> (col & 63)) & 1ULL) == 0) ++p;
        if (p == plan.rows) return plan;
        if (p != rank) {
            std::swap(a[p], a[rank]);
            plan.forward.push_back({p, rank, true});
        }
        plan.piv[col] = rank;
        for (uint32_t r = rank + 1; r < plan.rows; ++r) {
            if (((a[r][col >> 6] >> (col & 63)) & 1ULL) == 0) continue;
            for (uint32_t w = col >> 6; w < words; ++w) a[r][w] ^= a[rank][w];
            plan.forward.push_back({r, rank, false});
        }
        ++rank;
    }
    plan.back_dependencies.resize(plan.cols);
    for (uint32_t col = 0; col < plan.cols; ++col)
        for (uint32_t j = col + 1; j < plan.cols; ++j)
            if ((a[plan.piv[col]][j >> 6] >> (j & 63)) & 1ULL)
                plan.back_dependencies[col].push_back(j);
    plan.full_rank = true;
    return plan;
}

void apply_ls_plan(const LSPlan &plan, std::vector<uint8_t> &rhs, size_t len,
                   std::vector<uint8_t> &values) {
    for (const auto &op : plan.forward) {
        uint8_t *dst = rhs.data() + static_cast<uint64_t>(op.dst) * len;
        uint8_t *src = rhs.data() + static_cast<uint64_t>(op.src) * len;
        if (op.swap) {
            for (size_t k = 0; k < len; ++k) std::swap(dst[k], src[k]);
        } else {
            xor_bytes(dst, src, len);
        }
    }
    values.assign(static_cast<uint64_t>(plan.cols) * len, 0);
    for (int64_t col = static_cast<int64_t>(plan.cols) - 1; col >= 0; --col) {
        uint8_t *dst = values.data() + static_cast<uint64_t>(col) * len;
        std::memcpy(dst, rhs.data() + static_cast<uint64_t>(plan.piv[col]) * len, len);
        for (uint32_t j : plan.back_dependencies[col])
            xor_bytes(dst, values.data() + static_cast<uint64_t>(j) * len, len);
    }
}

// Independent Algorithm-4 path.  The legacy functions above are intentionally
// left unchanged so v3 remains a byte-for-byte source reference.
struct PaperLSPlan {
    bool full_rank = false;
    uint32_t rows = 0, cols = 0;
    std::vector<uint32_t> sorted_to_original;
    std::vector<uint32_t> pivot_rows;
    std::vector<std::pair<uint32_t, uint32_t>> forward;
    std::vector<std::vector<uint32_t>> back_dependencies;
    uint64_t matrix_nonzero_count = 0;
    uint64_t echelon_nonzero_count = 0;
    uint64_t fill_in_nonzero_count = 0;
    uint64_t forward_row_xor_count = 0;
    uint64_t backward_row_xor_count = 0;
    uint32_t sorted_max_row_span = 0;
    uint32_t echelon_max_row_span = 0;
};

struct WindowGF2Row {
    std::vector<uint64_t> bits;
    uint32_t lead = UINT32_MAX;
    uint32_t high = 0;
};

bool row_bit(const WindowGF2Row &row, uint32_t col) {
    return (row.bits[col >> 6] >> (col & 63)) & 1ULL;
}

uint32_t find_lead(const WindowGF2Row &row, uint32_t from, uint32_t cols) {
    if (from >= cols || row.lead == UINT32_MAX || from > row.high) return UINT32_MAX;
    uint32_t word = from >> 6;
    uint64_t x = row.bits[word] & (~uint64_t{0} << (from & 63));
    while (true) {
        if (x) return std::min<uint32_t>(cols, word * 64 + static_cast<uint32_t>(__builtin_ctzll(x)));
        ++word;
        if (word >= row.bits.size() || word * 64 > row.high) return UINT32_MAX;
        x = row.bits[word];
    }
}

PaperLSPlan build_paper_ls_plan(const Meta &m) {
    PaperLSPlan plan;
    plan.rows = m.h.out_count;
    plan.cols = static_cast<uint32_t>(m.h.qcap);
    const uint32_t words = (plan.cols + 63) / 64;
    struct Column { uint32_t original, start; std::vector<uint32_t> rows; };
    std::vector<Column> columns(plan.cols);
    for (uint32_t col = 0; col < plan.cols; ++col) {
        BandSample band = sample_band(m.assignment[col], plan.rows, m.h.band_width, m.h.ls_seed);
        columns[col] = {col, band.start, std::move(band.rows)};
    }
    std::stable_sort(columns.begin(), columns.end(), [](const Column &a, const Column &b) {
        return a.start < b.start;
    });
    plan.sorted_to_original.resize(plan.cols);
    std::vector<WindowGF2Row> matrix(plan.rows);
    for (auto &row : matrix) row.bits.assign(words, 0);
    for (uint32_t sorted = 0; sorted < plan.cols; ++sorted) {
        plan.sorted_to_original[sorted] = columns[sorted].original;
        for (uint32_t r : columns[sorted].rows) {
            matrix[r].bits[sorted >> 6] |= 1ULL << (sorted & 63);
            ++plan.matrix_nonzero_count;
        }
    }
    std::vector<std::vector<uint64_t>> original(plan.rows);
    for (uint32_t r = 0; r < plan.rows; ++r) {
        auto &row = matrix[r];
        row.lead = UINT32_MAX;
        for (uint32_t col = 0; col < plan.cols; ++col) if (row_bit(row, col)) {
            if (row.lead == UINT32_MAX) row.lead = col;
            row.high = col;
        }
        if (row.lead != UINT32_MAX)
            plan.sorted_max_row_span = std::max(plan.sorted_max_row_span, row.high - row.lead + 1);
        original[r] = row.bits;
    }

    // Rows are scheduled by their current leading one.  Thus elimination only
    // visits the active band/window and never scans unrelated matrix columns.
    std::vector<std::vector<uint32_t>> buckets(plan.cols);
    for (uint32_t r = 0; r < plan.rows; ++r)
        if (matrix[r].lead != UINT32_MAX) buckets[matrix[r].lead].push_back(r);
    plan.pivot_rows.assign(plan.cols, UINT32_MAX);
    for (uint32_t col = 0; col < plan.cols; ++col) {
        auto active = std::move(buckets[col]);
        if (active.empty()) return plan;
        uint32_t pivot = active.front();
        plan.pivot_rows[col] = pivot;
        const uint32_t first_word = col >> 6;
        for (size_t i = 1; i < active.size(); ++i) {
            uint32_t dst = active[i];
            uint32_t max_high = std::max(matrix[dst].high, matrix[pivot].high);
            uint32_t last_word = std::min<uint32_t>(words - 1, max_high >> 6);
            for (uint32_t word = first_word; word <= last_word; ++word)
                matrix[dst].bits[word] ^= matrix[pivot].bits[word];
            matrix[dst].high = max_high;
            matrix[dst].lead = find_lead(matrix[dst], col + 1, plan.cols);
            if (matrix[dst].lead != UINT32_MAX) {
                while (matrix[dst].high > matrix[dst].lead && !row_bit(matrix[dst], matrix[dst].high))
                    --matrix[dst].high;
                buckets[matrix[dst].lead].push_back(dst);
            }
            plan.forward.emplace_back(dst, pivot);
        }
    }

    plan.back_dependencies.resize(plan.cols);
    for (uint32_t col = 0; col < plan.cols; ++col) {
        const auto &row = matrix[plan.pivot_rows[col]];
        uint32_t last = col;
        for (uint32_t j = col; j < plan.cols; ++j) if (row_bit(row, j)) {
            ++plan.echelon_nonzero_count;
            last = j;
            if (j > col) plan.back_dependencies[col].push_back(j);
        }
        plan.echelon_max_row_span = std::max(plan.echelon_max_row_span, last - col + 1);
    }
    for (uint32_t r = 0; r < plan.rows; ++r)
        for (uint32_t col = 0; col < plan.cols; ++col)
            if (row_bit(matrix[r], col) && ((original[r][col >> 6] >> (col & 63)) & 1ULL) == 0)
                ++plan.fill_in_nonzero_count;
    plan.forward_row_xor_count = plan.forward.size();
    for (const auto &deps : plan.back_dependencies) plan.backward_row_xor_count += deps.size();
    plan.full_rank = true;
    return plan;
}

void apply_paper_range(const PaperLSPlan &plan, std::vector<uint8_t> &rhs, size_t len,
                       std::vector<uint8_t> &values, size_t begin, size_t end,
                       XorKernel kernel) {
    size_t count = end - begin;
    for (const auto &op : plan.forward) {
        uint8_t *dst = rhs.data() + static_cast<uint64_t>(op.first) * len + begin;
        const uint8_t *src = rhs.data() + static_cast<uint64_t>(op.second) * len + begin;
        xor_bytes_kernel(dst, src, count, kernel);
    }
    for (int64_t sorted = static_cast<int64_t>(plan.cols) - 1; sorted >= 0; --sorted) {
        uint32_t original = plan.sorted_to_original[static_cast<size_t>(sorted)];
        uint8_t *dst = values.data() + static_cast<uint64_t>(original) * len + begin;
        const uint8_t *src = rhs.data() + static_cast<uint64_t>(plan.pivot_rows[sorted]) * len + begin;
        std::memcpy(dst, src, count);
        for (uint32_t dep : plan.back_dependencies[sorted]) {
            uint32_t dep_original = plan.sorted_to_original[dep];
            xor_bytes_kernel(dst, values.data() + static_cast<uint64_t>(dep_original) * len + begin,
                             count, kernel);
        }
    }
}

void apply_paper_ls_plan(const PaperLSPlan &plan, std::vector<uint8_t> &rhs, size_t len,
                         std::vector<uint8_t> &values, uint32_t threads, XorKernel kernel) {
    values.assign(static_cast<uint64_t>(plan.cols) * len, 0);
    threads = std::max(1U, std::min<uint32_t>(threads, static_cast<uint32_t>(std::max<size_t>(1, len))));
    if (threads == 1) {
        apply_paper_range(plan, rhs, len, values, 0, len, kernel);
        return;
    }
    std::vector<std::thread> pool;
    for (uint32_t t = 0; t < threads; ++t) {
        size_t begin = len * t / threads, end = len * (t + 1) / threads;
        pool.emplace_back([&, begin, end] { apply_paper_range(plan, rhs, len, values, begin, end, kernel); });
    }
    for (auto &thread : pool) thread.join();
}

Meta make_ls_benchmark_meta(uint32_t q, uint32_t h, uint32_t c, uint32_t width,
                            uint64_t seed) {
    if (q == 0 || h < q || c < q || width == 0 || width > c)
        throw std::runtime_error("invalid LS benchmark parameters");
    Meta m;
    m.h.qcap = q;
    m.h.buckets = h;
    m.h.out_count = c;
    m.h.band_width = width;
    m.h.ls_seed = seed;
    m.h.pbc_seed = DEFAULT_PBC_SEED;
    m.queries.resize(q);
    uint64_t state = seed;
    std::unordered_set<uint64_t> used;
    for (uint64_t &query : m.queries) {
        do { state = splitmix64(state); query = state; } while (!used.insert(query).second);
    }
    m.assignment = schedule_genschedule(m.queries, h, DEFAULT_PBC_SEED,
                                        splitmix64(seed ^ 0x504243ULL));
    if (m.assignment.size() != q) throw std::runtime_error("benchmark PBC schedule failure");
    return m;
}

int ls_plan_metrics(int argc, char **argv) {
    if (argc < 7) throw std::runtime_error("ls_plan_metrics Q H C w seed");
    uint32_t q = static_cast<uint32_t>(std::stoul(argv[2]));
    uint32_t h = static_cast<uint32_t>(std::stoul(argv[3]));
    uint32_t c = static_cast<uint32_t>(std::stoul(argv[4]));
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[5]));
    uint64_t seed = std::stoull(argv[6]);
    Meta m = make_ls_benchmark_meta(q, h, c, width, seed);
    double legacy0 = now_seconds();
    LSPlan legacy = build_ls_plan(m);
    double legacy_time = now_seconds() - legacy0;
    double paper0 = now_seconds();
    PaperLSPlan paper = build_paper_ls_plan(m);
    double paper_time = now_seconds() - paper0;
    uint64_t legacy_forward_xor = 0, legacy_swaps = 0, legacy_backward = 0;
    for (const auto &op : legacy.forward) op.swap ? ++legacy_swaps : ++legacy_forward_xor;
    for (const auto &deps : legacy.back_dependencies) legacy_backward += deps.size();
    std::cout << "{\"phase\":\"ls_plan_metrics\",\"Q\":" << q
              << ",\"H\":" << h << ",\"C\":" << c << ",\"w\":" << width
              << ",\"legacy_full_rank\":" << (legacy.full_rank ? "true" : "false")
              << ",\"legacy_plan_seconds\":" << legacy_time
              << ",\"legacy_forward_row_xor_count\":" << legacy_forward_xor
              << ",\"legacy_row_swap_count\":" << legacy_swaps
              << ",\"legacy_backward_row_xor_count\":" << legacy_backward
              << ",\"legacy_total_row_xor_count\":" << legacy_forward_xor + legacy_backward
              << ",\"paper_full_rank\":" << (paper.full_rank ? "true" : "false")
              << ",\"paper_plan_seconds\":" << paper_time
              << ",\"matrix_nonzero_count\":" << paper.matrix_nonzero_count
              << ",\"sorted_max_row_span\":" << paper.sorted_max_row_span
              << ",\"echelon_max_row_span\":" << paper.echelon_max_row_span
              << ",\"fill_in_nonzero_count\":" << paper.fill_in_nonzero_count
              << ",\"forward_row_xor_count\":" << paper.forward_row_xor_count
              << ",\"backward_row_xor_count\":" << paper.backward_row_xor_count
              << ",\"total_row_xor_count\":"
              << paper.forward_row_xor_count + paper.backward_row_xor_count
              << ",\"row_xor_over_Qw\":"
              << static_cast<double>(paper.forward_row_xor_count + paper.backward_row_xor_count) /
                    (static_cast<double>(q) * width)
              << "}\n";
    return paper.full_rank && legacy.full_rank ? 0 : 3;
}

int ls_client_compare(int argc, char **argv) {
    if (argc < 12)
        throw std::runtime_error("ls_client_compare Q H C w S stripe seed threads kernel pattern");
    uint32_t q = static_cast<uint32_t>(std::stoul(argv[2]));
    uint32_t h = static_cast<uint32_t>(std::stoul(argv[3]));
    uint32_t c = static_cast<uint32_t>(std::stoul(argv[4]));
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[5]));
    uint64_t payload = std::stoull(argv[6]);
    uint64_t stripe = std::stoull(argv[7]);
    uint64_t seed = std::stoull(argv[8]);
    uint32_t threads = static_cast<uint32_t>(std::stoul(argv[9]));
    std::string kernel_name = argv[10], pattern = argv[11];
    bool optimized_only = argc > 12 && std::string(argv[12]) == "optimized_only";
    XorKernel kernel = parse_xor_kernel(kernel_name);
    Meta m = make_ls_benchmark_meta(q, h, c, width, seed);
    double p0 = now_seconds();
    LSPlan legacy = build_ls_plan(m);
    double legacy_plan_seconds = now_seconds() - p0;
    p0 = now_seconds();
    PaperLSPlan paper = build_paper_ls_plan(m);
    double paper_plan_seconds = now_seconds() - p0;
    if (!legacy.full_rank || !paper.full_rank) throw std::runtime_error("rank failure");
    double encode_seconds = 0, legacy_seconds = 0, scalar_seconds = 0, optimized_seconds = 0;
    double legacy_cpu = 0, scalar_cpu = 0, optimized_cpu = 0;
    bool legacy_ok = true, scalar_ok = true, optimized_ok = true, scalar_matches_legacy = true,
         optimized_matches_legacy = true;
    uint64_t stripes = (payload + stripe - 1) / stripe;
    for (uint64_t st = 0; st < stripes; ++st) {
        uint64_t offset = st * stripe;
        size_t len = static_cast<size_t>(std::min<uint64_t>(stripe, payload - offset));
        std::vector<uint8_t> expected(static_cast<uint64_t>(q) * len, 0);
        if (pattern != "zero") {
            uint32_t populated = pattern == "single" ? 1 : q;
            for (uint32_t col = 0; col < populated; ++col)
                fill_bytes(static_cast<uint64_t>(col) + 1, seed, offset,
                           expected.data() + static_cast<uint64_t>(col) * len, len);
        }
        std::vector<uint8_t> encoded(static_cast<uint64_t>(c) * len, 0);
        double e0 = now_seconds();
        for (uint32_t col = 0; col < q; ++col) {
            const uint8_t *src = expected.data() + static_cast<uint64_t>(col) * len;
            for (uint32_t row : band_rows(m.assignment[col], c, width, seed))
                xor_bytes(encoded.data() + static_cast<uint64_t>(row) * len, src, len);
        }
        encode_seconds += now_seconds() - e0;

        std::vector<uint8_t> rhs, legacy_values;
        double c0, t0;
        if (!optimized_only) {
            rhs = encoded;
            c0 = cpu_seconds(); t0 = now_seconds();
            apply_ls_plan(legacy, rhs, len, legacy_values);
            legacy_seconds += now_seconds() - t0;
            legacy_cpu += cpu_seconds() - c0;
            legacy_ok &= legacy_values == expected;
        }

        rhs = encoded;
        std::vector<uint8_t> scalar_values;
        if (!optimized_only) {
            c0 = cpu_seconds(); t0 = now_seconds();
            apply_paper_ls_plan(paper, rhs, len, scalar_values, 1, XorKernel::Scalar);
            scalar_seconds += now_seconds() - t0;
            scalar_cpu += cpu_seconds() - c0;
            scalar_ok &= scalar_values == expected;
            scalar_matches_legacy &= scalar_values == legacy_values;
        }

        rhs = encoded;
        std::vector<uint8_t> optimized_values;
        c0 = cpu_seconds(); t0 = now_seconds();
        apply_paper_ls_plan(paper, rhs, len, optimized_values, threads, kernel);
        optimized_seconds += now_seconds() - t0;
        optimized_cpu += cpu_seconds() - c0;
        optimized_ok &= optimized_values == expected;
        optimized_matches_legacy &= optimized_only ? (optimized_values == expected)
                                                   : (optimized_values == legacy_values);
    }
    uint64_t legacy_forward = 0, legacy_backward = 0, legacy_swaps = 0;
    for (const auto &op : legacy.forward) op.swap ? ++legacy_swaps : ++legacy_forward;
    for (const auto &deps : legacy.back_dependencies) legacy_backward += deps.size();
    auto emit = [&](const char *mode, uint32_t nthreads, const std::string &used_kernel,
                    double plan_time, double wall, double cpu, uint64_t forward,
                    uint64_t backward, bool ok, bool matches) {
        uint64_t row_xors = forward + backward;
        uint64_t logical = row_xors * payload;
        std::cout << "{\"phase\":\"ls_client_compare\",\"implementation_mode\":\"" << mode
                  << "\",\"Q\":" << q << ",\"H\":" << h << ",\"C\":" << c
                  << ",\"w\":" << width << ",\"S\":" << payload
                  << ",\"thread_count\":" << nthreads << ",\"kernel\":\"" << used_kernel
                  << "\",\"pattern\":\"" << pattern << "\",\"plan_build_time\":" << plan_time
                  << ",\"payload_apply_time\":" << wall << ",\"cpu_time\":" << cpu
                  << ",\"forward_row_xor_count\":" << forward
                  << ",\"backward_row_xor_count\":" << backward
                  << ",\"total_row_xor_count\":" << row_xors
                  << ",\"total_logical_xor_bytes\":" << logical
                  << ",\"estimated_physical_memory_bytes\":" << 3ULL * logical
                  << ",\"logical_xor_GiB_per_second\":"
                  << (wall ? logical / static_cast<double>(1ULL << 30) / wall : 0)
                  << ",\"peak_rss_kib\":" << peak_rss_kib()
                  << ",\"content_equality\":" << (ok ? "true" : "false")
                  << ",\"matches_legacy\":" << (matches ? "true" : "false")
                  << ",\"shared_input_encode_seconds\":" << encode_seconds << "}\n";
    };
    if (!optimized_only) {
        emit("legacy_reference", 1, "scalar", legacy_plan_seconds, legacy_seconds, legacy_cpu,
             legacy_forward, legacy_backward, legacy_ok, true);
        emit("paper_faithful_scalar", 1, "scalar", paper_plan_seconds, scalar_seconds, scalar_cpu,
             paper.forward_row_xor_count, paper.backward_row_xor_count, scalar_ok, scalar_matches_legacy);
    }
    emit("paper_faithful_optimized", threads, kernel_name, paper_plan_seconds, optimized_seconds,
         optimized_cpu, paper.forward_row_xor_count, paper.backward_row_xor_count,
         optimized_ok, optimized_matches_legacy);
    return legacy_ok && scalar_ok && optimized_ok && scalar_matches_legacy && optimized_matches_legacy ? 0 : 4;
}

int ls_server_compare(int argc, char **argv) {
    if (argc < 10)
        throw std::runtime_error("ls_server_compare H C w S stripe seed threads kernel");
    uint32_t h = static_cast<uint32_t>(std::stoul(argv[2]));
    uint32_t c = static_cast<uint32_t>(std::stoul(argv[3]));
    uint32_t width = static_cast<uint32_t>(std::stoul(argv[4]));
    uint64_t payload = std::stoull(argv[5]);
    uint64_t stripe = std::stoull(argv[6]);
    uint64_t seed = std::stoull(argv[7]);
    uint32_t threads = static_cast<uint32_t>(std::stoul(argv[8]));
    std::string kernel_name = argv[9];
    bool optimized_only = argc > 10 && std::string(argv[10]) == "optimized_only";
    XorKernel kernel = parse_xor_kernel(kernel_name);
    std::vector<std::vector<uint32_t>> column_targets(h), row_sources(c);
    uint64_t matrix_nonzeros = 0;
    double schedule0 = now_seconds();
    for (uint32_t b = 0; b < h; ++b) {
        column_targets[b] = band_rows(b, c, width, seed);
        matrix_nonzeros += column_targets[b].size();
        for (uint32_t row : column_targets[b]) row_sources[row].push_back(b);
    }
    double schedule_seconds = now_seconds() - schedule0;
    double legacy_seconds = 0, scalar_seconds = 0, row_seconds = 0, column_seconds = 0;
    double legacy_cpu = 0, scalar_cpu = 0, row_cpu = 0, column_cpu = 0;
    bool scalar_ok = true, row_ok = true, column_ok = true;
    SHA256_CTX row_hash_ctx;
    SHA256_Init(&row_hash_ctx);
    uint64_t stripes = (payload + stripe - 1) / stripe;
    for (uint64_t st = 0; st < stripes; ++st) {
        uint64_t offset = st * stripe;
        size_t len = static_cast<size_t>(std::min<uint64_t>(stripe, payload - offset));
        std::vector<uint8_t> raw(static_cast<uint64_t>(h) * len);
        for (uint32_t b = 0; b < h; ++b)
            fill_bytes(static_cast<uint64_t>(b) + 1, seed, offset,
                       raw.data() + static_cast<uint64_t>(b) * len, len);
        std::vector<uint8_t> legacy;
        double cpu0, wall0;
        if (!optimized_only) {
            legacy.assign(static_cast<uint64_t>(c) * len, 0);
            cpu0 = cpu_seconds(); wall0 = now_seconds();
            for (uint32_t b = 0; b < h; ++b)
                for (uint32_t row : band_rows(b, c, width, seed))
                    xor_bytes(legacy.data() + static_cast<uint64_t>(row) * len,
                              raw.data() + static_cast<uint64_t>(b) * len, len);
            legacy_seconds += now_seconds() - wall0; legacy_cpu += cpu_seconds() - cpu0;

            std::vector<uint8_t> scalar(static_cast<uint64_t>(c) * len, 0);
            cpu0 = cpu_seconds(); wall0 = now_seconds();
            for (uint32_t b = 0; b < h; ++b)
                for (uint32_t row : column_targets[b])
                    xor_bytes(scalar.data() + static_cast<uint64_t>(row) * len,
                              raw.data() + static_cast<uint64_t>(b) * len, len);
            scalar_seconds += now_seconds() - wall0; scalar_cpu += cpu_seconds() - cpu0;
            scalar_ok &= scalar == legacy;
        }

        std::vector<uint8_t> row_major(static_cast<uint64_t>(c) * len, 0);
        cpu0 = cpu_seconds(); wall0 = now_seconds();
        std::vector<std::thread> workers;
        for (uint32_t tid = 0; tid < threads; ++tid) workers.emplace_back([&, tid] {
            for (uint32_t row = tid; row < c; row += threads) {
                uint8_t *dst = row_major.data() + static_cast<uint64_t>(row) * len;
                for (uint32_t b : row_sources[row])
                    xor_bytes_kernel(dst, raw.data() + static_cast<uint64_t>(b) * len, len, kernel);
            }
        });
        for (auto &worker : workers) worker.join();
        row_seconds += now_seconds() - wall0; row_cpu += cpu_seconds() - cpu0;
        if (!optimized_only) row_ok &= row_major == legacy;
        SHA256_Update(&row_hash_ctx, row_major.data(), row_major.size());

        if (!optimized_only) {
            std::vector<uint8_t> column_major(static_cast<uint64_t>(c) * len, 0);
            cpu0 = cpu_seconds(); wall0 = now_seconds(); workers.clear();
            for (uint32_t tid = 0; tid < threads; ++tid) workers.emplace_back([&, tid] {
                size_t begin = len * tid / threads, end = len * (tid + 1) / threads;
                for (uint32_t b = 0; b < h; ++b)
                    for (uint32_t row : column_targets[b])
                        xor_bytes_kernel(column_major.data() + static_cast<uint64_t>(row) * len + begin,
                                         raw.data() + static_cast<uint64_t>(b) * len + begin,
                                         end - begin, kernel);
            });
            for (auto &worker : workers) worker.join();
            column_seconds += now_seconds() - wall0; column_cpu += cpu_seconds() - cpu0;
            column_ok &= column_major == legacy;
        }
    }
    unsigned char row_digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(row_digest, &row_hash_ctx);
    std::ostringstream row_digest_hex;
    for (unsigned char byte : row_digest)
        row_digest_hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    auto emit = [&](const char *mode, uint32_t nthreads, const char *layout, const char *used_kernel,
                    double wall, double cpu, bool ok) {
        uint64_t logical = matrix_nonzeros * payload;
        std::cout << "{\"phase\":\"ls_server_compare\",\"implementation_mode\":\"" << mode
                  << "\",\"Q\":1024,\"H\":" << h << ",\"C\":" << c << ",\"w\":" << width
                  << ",\"S\":" << payload << ",\"thread_count\":" << nthreads
                  << ",\"kernel\":\"" << used_kernel << "\",\"encode_layout\":\"" << layout
                  << "\",\"schedule_build_seconds\":" << schedule_seconds
                  << ",\"matrix_nonzero_count\":" << matrix_nonzeros
                  << ",\"payload_apply_time\":" << wall << ",\"cpu_time\":" << cpu
                  << ",\"total_logical_xor_bytes\":" << logical
                  << ",\"estimated_physical_memory_bytes\":" << 3ULL * logical
                  << ",\"logical_xor_GiB_per_second\":"
                  << (wall ? logical / static_cast<double>(1ULL << 30) / wall : 0)
                  << ",\"peak_rss_kib\":" << peak_rss_kib()
                  << ",\"output_sha256\":\"" << row_digest_hex.str() << "\""
                  << ",\"content_equality\":" << (ok ? "true" : "false") << "}\n";
    };
    if (!optimized_only) {
        emit("legacy_reference", 1, "column_major", "scalar", legacy_seconds, legacy_cpu, true);
        emit("paper_faithful_scalar", 1, "column_major_precomputed", "scalar", scalar_seconds, scalar_cpu, scalar_ok);
    }
    emit("paper_faithful_optimized", threads, "row_major", kernel_name.c_str(), row_seconds, row_cpu, row_ok);
    if (!optimized_only)
        emit("paper_faithful_optimized", threads, "column_major", kernel_name.c_str(), column_seconds, column_cpu, column_ok);
    return scalar_ok && row_ok && column_ok ? 0 : 5;
}

int recover(int argc, char **argv) {
    if (argc < 7) throw std::runtime_error("recover meta response0 response1 stripe expected_version [client_output|-] [implementation_mode] [threads] [kernel] [expected_database_image] [all_slots|real_only]");
    Meta m = read_meta(argv[2]);
    uint64_t stripe = std::stoull(argv[5]), expected_version = std::stoull(argv[6]);
    std::string implementation_mode = argc > 8 ? argv[8] : "paper_faithful_optimized";
    uint32_t thread_count = argc > 9 ? static_cast<uint32_t>(std::stoul(argv[9])) : 1;
    std::string kernel_name = argc > 10 ? argv[10] : "scalar";
    std::string expected_database_path = argc > 11 ? argv[11] : "";
    std::string output_mode = argc > 12 ? argv[12] : "all_slots";
    std::string matrix_path = argc > 13 ? argv[13] : "";
    if((m.h.scheduler_kind & 0x80000000U) && matrix_path.empty())
        throw std::runtime_error("missing explicit OCC Setup randomness");
    if(!matrix_path.empty() && (m.h.band_width!=m.h.out_count||m.h.out_count!=m.h.qcap+m.h.lambda_rank||m.h.ls_seed!=0))
        throw std::runtime_error("client explicit OCC parameters");
    load_ls_matrix(matrix_path,m.h.out_count,m.h.buckets);
    if (output_mode != "all_slots" && output_mode != "real_only")
        throw std::runtime_error("recover output mode must be all_slots|real_only");
    std::ifstream expected_database;
    if (!expected_database_path.empty() && expected_database_path != "AEAD") {
        expected_database.open(expected_database_path, std::ios::binary);
        if (!expected_database) throw std::runtime_error("cannot open expected database image");
    }
    if (implementation_mode != "legacy_reference" && implementation_mode != "paper_faithful_scalar" &&
        implementation_mode != "paper_faithful_optimized")
        throw std::runtime_error("invalid client implementation mode");
    if (implementation_mode == "paper_faithful_scalar") { thread_count = 1; kernel_name = "scalar"; }
    if (implementation_mode == "legacy_reference") { thread_count = 1; kernel_name = "scalar"; }
    XorKernel kernel = parse_xor_kernel(kernel_name);
    // Version is public, but keep even this failure on the fixed response-
    // consumption path.  The externally exposed API maps all codes below to
    // one C-local error.
    bool epoch_mismatch = m.h.version != expected_version;
    double wall0 = now_seconds(), cpu0 = cpu_seconds();
    double plan0 = now_seconds();
    LSPlan ls_plan;
    PaperLSPlan paper_plan;
    if (m.h.compressed && !m.h.schedule_failed) {
        if (implementation_mode == "legacy_reference") ls_plan = build_ls_plan(m);
        else paper_plan = build_paper_ls_plan(m);
    }
    double ls_plan_seconds = now_seconds() - plan0;
    bool plan_full_rank = implementation_mode == "legacy_reference" ? ls_plan.full_rank : paper_plan.full_rank;
    bool ls_rank_failed = m.h.compressed && !m.h.schedule_failed && !plan_full_rank;
    std::ifstream r0(argv[3], std::ios::binary), r1(argv[4], std::ios::binary);
    uint64_t stripes = (m.h.s + stripe - 1) / stripe;
    uint64_t checked = 0, dummy_zero_checked = 0;
    bool response_mismatch = false, dummy_mismatch = false;
    std::ofstream recovered;
    bool write_recovered = argc > 7 && std::string(argv[7]) != "-";
    if (write_recovered) {
        recovered.open(argv[7], std::ios::binary | std::ios::trunc);
        if (!recovered) throw std::runtime_error("cannot open client recovery output");
    }
    double ls_decode_seconds = 0, response_read_seconds = 0, share_merge_seconds = 0;
    std::vector<uint8_t> reusable_a, reusable_b, reusable_values, merge_chunk;
    for (uint64_t st = 0; st < stripes; ++st) {
        uint64_t offset = st * stripe;
        size_t len = static_cast<size_t>(std::min<uint64_t>(stripe, m.h.s - offset));
        reusable_a.resize(static_cast<uint64_t>(m.h.out_count) * len);
        double read0 = now_seconds();
        r0.read(reinterpret_cast<char *>(reusable_a.data()), reusable_a.size());
        if (!r0) throw std::runtime_error("truncated response0");
        response_read_seconds += now_seconds() - read0;
        if (implementation_mode == "paper_faithful_optimized") {
            merge_chunk.resize(std::min<size_t>(1U << 20, reusable_a.size()));
            size_t done = 0;
            while (done < reusable_a.size()) {
                size_t take = std::min(merge_chunk.size(), reusable_a.size() - done);
                read0 = now_seconds();
                r1.read(reinterpret_cast<char *>(merge_chunk.data()), take);
                if (!r1) throw std::runtime_error("truncated response1");
                response_read_seconds += now_seconds() - read0;
                double merge0 = now_seconds();
                xor_bytes_kernel(reusable_a.data() + done, merge_chunk.data(), take, kernel);
                share_merge_seconds += now_seconds() - merge0;
                done += take;
            }
        } else {
            reusable_b.resize(reusable_a.size());
            read0 = now_seconds();
            r1.read(reinterpret_cast<char *>(reusable_b.data()), reusable_b.size());
            if (!r1) throw std::runtime_error("truncated response1");
            response_read_seconds += now_seconds() - read0;
            double merge0 = now_seconds();
            xor_bytes(reusable_a.data(), reusable_b.data(), reusable_a.size());
            share_merge_seconds += now_seconds() - merge0;
        }
        auto &a = reusable_a;
        auto &values = reusable_values;
        if (m.h.compressed) {
            double ls0 = now_seconds();
            if (!ls_rank_failed && !m.h.schedule_failed) {
                if (implementation_mode == "legacy_reference") apply_ls_plan(ls_plan, a, len, values);
                else apply_paper_ls_plan(paper_plan, a, len, values, thread_count, kernel);
            }
            ls_decode_seconds += now_seconds() - ls0;
        } else {
            values.resize(m.h.qcap * len);
            for (uint64_t i = 0; i < m.h.qcap; ++i)
                std::memcpy(values.data() + i * len, a.data() + m.assignment[i] * len, len);
        }
        // Validate and emit all Q slots with identical byte work.  Earlier
        // versions used separate qreal and dummy loops and wrote only qreal
        // blocks, which made the client completion time and output length a
        // deterministic function of q.  The real/dummy mask is client-local;
        // every slot still executes fill, mask, compare and (when requested)
        // the same fixed-size write.
        std::vector<uint8_t> expected(len);
        for (uint64_t i = 0; i < m.h.qcap && !m.h.schedule_failed && !ls_rank_failed; ++i) {
            if (expected_database_path == "AEAD" && i < m.h.qreal) {
                // Client lacks the snapshot; application authenticates ciphertext with per-file GCM.
                std::memcpy(expected.data(), values.data() + i * len, len);
            } else if (!expected_database_path.empty() && i < m.h.qreal) {
                expected_database.clear();
                expected_database.seekg(static_cast<std::streamoff>(m.queries[i] * m.h.s + offset));
                expected_database.read(reinterpret_cast<char *>(expected.data()), len);
                if (!expected_database) throw std::runtime_error("truncated expected database image");
            } else if (!expected_database_path.empty()) {
                std::memset(expected.data(), 0, len);
            } else {
                fill_bytes(m.queries[i], m.h.version, offset, expected.data(), len);
            }
            const uint8_t real_mask = static_cast<uint8_t>(0U - static_cast<unsigned>(i < m.h.qreal));
            for (size_t k = 0; k < len; ++k) expected[k] &= real_mask;
            if (std::memcmp(expected.data(), values.data() + i * len, len) != 0) {
                if (i < m.h.qreal) response_mismatch = true;
                else dummy_mismatch = true;
            }
            if (write_recovered && (output_mode == "all_slots" || i < m.h.qreal)) {
                recovered.seekp(static_cast<std::streamoff>(i * m.h.s + offset));
                recovered.write(reinterpret_cast<const char *>(values.data() + i * len), len);
                if (!recovered) throw std::runtime_error("client recovery output write failed");
            }
            if (i < m.h.qreal) checked += len;
            else dummy_zero_checked += len;
        }
    }
    if (ls_rank_failed) {
        std::cerr << "LS matrix rank failure after fixed-length response consumption\n";
        return 43;
    }
    if (m.h.schedule_failed) {
        std::cerr << "client-local schedule failure after fixed-length response consumption\n";
        return 46;
    }
    if (epoch_mismatch) {
        std::cerr << "client-local epoch mismatch after fixed-length response consumption\n";
        return 44;
    }
    if (response_mismatch) {
        std::cerr << "response mismatch after fixed-length response consumption\n";
        return 45;
    }
    if (dummy_mismatch) {
        std::cerr << "virtual dummy recovered non-zero after fixed-length response consumption\n";
        return 47;
    }
    if (write_recovered) recovered.flush();
    std::cout << "{\"phase\":\"recover\",\"checked_bytes\":" << checked
              << ",\"implementation_mode\":\"" << implementation_mode << "\""
              << ",\"thread_count\":" << thread_count
              << ",\"kernel\":\"" << kernel_name << "\""
              << ",\"dummy_zero_checked_bytes\":" << dummy_zero_checked
              << ",\"ls_decode_seconds\":" << ls_decode_seconds
              << ",\"ls_plan_seconds\":" << ls_plan_seconds
              << ",\"response_read_seconds\":" << response_read_seconds
              << ",\"share_merge_seconds\":" << share_merge_seconds
              << ",\"total_logical_xor_bytes\":"
              << (implementation_mode == "legacy_reference"
                    ? [&] { uint64_t n = 0; for (const auto &op : ls_plan.forward) if (!op.swap) ++n;
                              for (const auto &d : ls_plan.back_dependencies) n += d.size(); return n * m.h.s; }()
                    : (paper_plan.forward_row_xor_count + paper_plan.backward_row_xor_count) * m.h.s)
              << ",\"response_bytes_read\":" << 2ULL * m.h.out_count * m.h.s
              << ",\"recovered_output_bytes\":" << (write_recovered ? (output_mode == "real_only" ? m.h.qreal : m.h.qcap) * m.h.s : 0)
              << ",\"wall_seconds\":" << now_seconds() - wall0
              << ",\"cpu_seconds\":" << cpu_seconds() - cpu0
              << ",\"peak_rss_kib\":" << peak_rss_kib() << "}\n";
    return 0;
}

int selftest() {
    for (uint32_t logn : {8U, 11U, 16U}) {
        uint64_t n = 1ULL << logn;
        uint64_t target = n / 3;
        auto keys = DPF::Gen(target, logn);
        const uint64_t probes[] = {uint64_t{0}, target, n - 1};
        for (uint64_t x : probes) {
            bool v = DPF::Eval(keys.first, x, logn) ^ DPF::Eval(keys.second, x, logn);
            if (v != (x == target)) throw std::runtime_error("DPF selftest failed");
        }
    }
    auto random_a = DPF::Gen(17, 8);
    auto random_b = DPF::Gen(17, 8);
    if (random_a.first == random_b.first && random_a.second == random_b.second)
        throw std::runtime_error("DPF CSPRNG selftest produced duplicate key pairs");
    std::vector<uint64_t> q{1, 2, 3, 4, 5, 6, 7, 8};
    auto gs = schedule_genschedule(q, 12, DEFAULT_PBC_SEED, 7);
    if (gs.size() != q.size()) throw std::runtime_error("GenSchedule selftest failed");
    std::unordered_set<uint64_t> buckets(gs.begin(), gs.end());
    if (buckets.size() != q.size()) throw std::runtime_error("GenSchedule collision selftest failed");
    bool saw_zero_band = false, saw_nonzero_band = false;
    for (uint64_t i = 0; i < 4096; ++i) {
        auto band = sample_band(i, 32, 8, DEFAULT_LS_SEED);
        saw_zero_band |= band.rows.empty();
        saw_nonzero_band |= !band.rows.empty();
        for (uint32_t row : band.rows)
            if (row < band.start || row >= band.start + 8)
                throw std::runtime_error("LS band selftest escaped range");
    }
    if (!saw_zero_band || !saw_nonzero_band)
        throw std::runtime_error("LS all-zero-band semantics selftest failed");
    if (!ls_full_column_rank(8, 20, 20, DEFAULT_LS_SEED))
        throw std::runtime_error("LS dense rank selftest unexpectedly failed");
    std::cout << "selftest ok\n";
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 2) throw std::runtime_error("expected command: selftest|prepare|server|serve|pir_ablation|recover|schedule_trials|ls_trials|ls_rank_trials|ls_distribution_audit|ls_plan_metrics|ls_client_compare|ls_server_compare");
        std::string cmd = argv[1];
        if (cmd == "selftest") return selftest();
        if (cmd == "prepare") return prepare(argc, argv);
        if (cmd == "server") return server(argc, argv);
        if (cmd == "serve") return serve(argc, argv);
        if (cmd == "pir_ablation") return pir_ablation(argc, argv);
        if (cmd == "recover") return recover(argc, argv);
        if (cmd == "schedule_trials") return schedule_trials(argc, argv);
        if (cmd == "ls_trials") return ls_trials(argc, argv);
        if (cmd == "ls_rank_trials") return ls_rank_trials(argc, argv);
        if (cmd == "ls_distribution_audit") return ls_distribution_audit(argc, argv);
        if (cmd == "ls_plan_metrics") return ls_plan_metrics(argc, argv);
        if (cmd == "ls_client_compare") return ls_client_compare(argc, argv);
        if (cmd == "ls_server_compare") return ls_server_compare(argc, argv);
        throw std::runtime_error("unknown command");
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}
