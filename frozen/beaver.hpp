#pragma once
#include "match.hpp"
#include <immintrin.h>

namespace pbm {
struct PlannedGate {
    Gate gate;
    unsigned output, slot;
};
struct BooleanPlan {
    std::vector<std::vector<PlannedGate>> layers;
    unsigned products = 0;
    std::size_t max_products = 0;
    BooleanPlan(const Formula& f, unsigned k) : layers(f.depth + 1) {
        for (unsigned i = 0; i < f.gates.size(); ++i) {
            const auto g = f.gates[i];
            layers[g.level].push_back({g, k + i, 0});
        }
        for (auto& layer : layers) {
            std::size_t active = 0;
            for (auto& g : layer)
                if (g.gate.op != '!') {
                    g.slot = products++;
                    ++active;
                }
            max_products = std::max(max_products, active);
        }
    }
};

struct TripleDealer {

    static std::array<Bytes, 2> generate(const BooleanPlan& plan, std::size_t n) {
        const auto w = bytes(n);
        std::array<Bytes, 2> parties{Bytes(3 * w * plan.products), Bytes(3 * w * plan.products)};
        auto a = random_bits(n), b = random_bits(n);
        for (unsigned gate = 0; gate < plan.products; ++gate) {
            const auto offset = 3 * w * gate;
            random_bytes(a.data(), w);
            random_bytes(b.data(), w);
            clear_tail(a, n);
            clear_tail(b, n);
            auto* c = parties[0].data() + offset;
            auto* s = parties[1].data() + offset;
            random_bytes(c, 3 * w);
            if (n % 8)
                for (unsigned p = 0; p < 3; ++p)
                    c[(p + 1) * w - 1] &= Byte((1u << (n % 8)) - 1);
            for (std::size_t j = 0; j < w; ++j) {
                s[j] = c[j] ^ a[j];
                s[w + j] = c[w + j] ^ b[j];
                s[2 * w + j] = c[2 * w + j] ^ (a[j] & b[j]);
            }
        }
        return parties;
    }
};

inline std::vector<Triple> legacy_triples(const BooleanPlan& plan, const Formula& f, unsigned k,
                                          const Bytes& pool, std::size_t w) {
    std::vector<unsigned> position(f.gates.size());
    for (const auto& layer : plan.layers)
        for (auto g : layer)
            position[g.output - k] = g.slot;
    std::vector<Triple> triples;
    for (unsigned i = 0; i < f.gates.size(); ++i) {
        if (f.gates[i].op == '!')
            continue;
        const auto start = pool.begin() + 3 * w * position[i];
        triples.push_back({Bytes(start, start + w), Bytes(start + w, start + 2 * w),
                           Bytes(start + 2 * w, start + 3 * w)});
    }
    return triples;
}

struct KernelArgs {
    Byte *d, *e, *out;
    const Byte *peer_d, *peer_e, *x, *y, *a, *b, *c;
    std::size_t length;
    bool client, is_or;
};
using Kernel = void (*)(const KernelArgs&, bool);

__attribute__((optimize("no-tree-vectorize"))) inline void kernel_scalar(const KernelArgs& p,
                                                                         bool finish) {
    for (std::size_t j = 0; j < p.length; ++j) {
        if (!finish) {
            p.d[j] = p.x[j] ^ p.a[j];
            p.e[j] = p.y[j] ^ p.b[j];
        } else {
            const Byte d = p.d[j] ^ p.peer_d[j], e = p.e[j] ^ p.peer_e[j];
            p.out[j] = p.c[j] ^ (d & p.b[j]) ^ (e & p.a[j]) ^ (p.client ? (d & e) : 0) ^
                       (p.is_or ? (p.x[j] ^ p.y[j]) : 0);
        }
    }
}
inline KernelArgs tail(KernelArgs p, std::size_t i) {
    p.d += i;
    p.e += i;
    p.x += i;
    p.y += i;
    p.a += i;
    p.b += i;
    p.c += i;
    if (p.out)
        p.out += i;
    if (p.peer_d)
        p.peer_d += i;
    if (p.peer_e)
        p.peer_e += i;
    p.length -= i;
    return p;
}

__attribute__((optimize("no-tree-vectorize"))) inline void kernel_u64(const KernelArgs& p,
                                                                      bool finish) {
    const auto load = [](const Byte* ptr) {
        Word x;
        std::memcpy(&x, ptr, 8);
        return x;
    };
    const auto put = [](Byte* ptr, Word x) { std::memcpy(ptr, &x, 8); };
    std::size_t j = 0;
    for (; j + 8 <= p.length; j += 8) {
        const Word x = load(p.x + j), y = load(p.y + j), a = load(p.a + j), b = load(p.b + j);
        if (!finish) {
            put(p.d + j, x ^ a);
            put(p.e + j, y ^ b);
        } else {
            const Word d = load(p.d + j) ^ load(p.peer_d + j),
                       e = load(p.e + j) ^ load(p.peer_e + j);
            put(p.out + j, load(p.c + j) ^ (d & b) ^ (e & a) ^ (p.client ? (d & e) : 0) ^
                               (p.is_or ? (x ^ y) : 0));
        }
    }
    kernel_scalar(tail(p, j), finish);
}

#define PBM_SIMD(NAME, TARGET, SIZE, V, LOAD, STORE, XOR, AND)                                     \
    __attribute__((target(TARGET))) inline void NAME(const KernelArgs& p, bool finish) {           \
        std::size_t j = 0;                                                                         \
        for (; j + SIZE <= p.length; j += SIZE) {                                                  \
            const V a = LOAD(p.a + j), b = LOAD(p.b + j);                                          \
            if (!finish) {                                                                         \
                STORE(p.d + j, XOR(LOAD(p.x + j), a));                                             \
                STORE(p.e + j, XOR(LOAD(p.y + j), b));                                             \
            } else {                                                                               \
                const V d = XOR(LOAD(p.d + j), LOAD(p.peer_d + j)),                                \
                        e = XOR(LOAD(p.e + j), LOAD(p.peer_e + j));                                \
                auto z = XOR(LOAD(p.c + j), XOR(AND(d, b), AND(e, a)));                            \
                if (p.client)                                                                      \
                    z = XOR(z, AND(d, e));                                                         \
                if (p.is_or)                                                                       \
                    z = XOR(z, XOR(LOAD(p.x + j), LOAD(p.y + j)));                                 \
                STORE(p.out + j, z);                                                               \
            }                                                                                      \
        }                                                                                          \
        kernel_u64(tail(p, j), finish);                                                            \
    }
#define LD256(p) _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p))
#define ST256(p, x) _mm256_storeu_si256(reinterpret_cast<__m256i*>(p), x)
PBM_SIMD(kernel_avx2, "avx2", 32, __m256i, LD256, ST256, _mm256_xor_si256, _mm256_and_si256)
PBM_SIMD(kernel_avx512, "avx512f", 64, __m512i, _mm512_loadu_si512, _mm512_storeu_si512,
         _mm512_xor_si512, _mm512_and_si512)
#undef PBM_SIMD
#undef LD256
#undef ST256

inline Kernel choose_kernel(const std::string& name) {
    if (name == "scalar")
        return kernel_scalar;
    if (name == "u64")
        return kernel_u64;
    if (name == "avx2" && __builtin_cpu_supports("avx2"))
        return kernel_avx2;
    if (name == "avx512" && __builtin_cpu_supports("avx512f"))
        return kernel_avx512;
    throw std::runtime_error("Unsupported Beaver kernel");
}

struct BooleanWorkspace {
    std::vector<Bytes> shares;
    Bytes local, peer, transposed;
    BooleanWorkspace(const BooleanPlan& plan, const Formula& f, unsigned k, std::size_t w,
                     bool record)
        : shares(k + f.gates.size()), local(2 * w * plan.max_products), peer(local.size()),
          transposed(record ? local.size() : 0) {
        for (std::size_t i = k; i < shares.size(); ++i)
            shares[i].resize(w);
    }
};

inline Bytes boolean_packed(Tcp& tcp, bool server, const Formula& f, const BooleanPlan& plan,
                            std::vector<Bytes> inputs, const Bytes& triples, std::size_t n,
                            Kernel kernel, const std::string& layout, BooleanWorkspace& w,
                            unsigned& rounds, double& local_ms) {
    const auto width = bytes(n);
    for (unsigned i = 0; i < inputs.size(); ++i)
        w.shares[i] = std::move(inputs[i]);
    for (unsigned level = 1; level < plan.layers.size(); ++level) {
        auto tick = Clock::now();
        const auto& layer = plan.layers[level];
        const auto count =
            std::count_if(layer.begin(), layer.end(), [](auto g) { return g.gate.op != '!'; });
        unsigned index = 0;
        const auto offset = [&](unsigned gate, unsigned arm) {
            return width * (layout == "column" ? arm * count + gate : 2 * gate + arm);
        };
        auto arguments = [&](const PlannedGate& g, unsigned ix) {
            const auto t = triples.data() + 3 * width * g.slot;
            const auto d = offset(ix, 0), e = offset(ix, 1);
            return KernelArgs{w.local.data() + d,
                              w.local.data() + e,
                              w.shares[g.output].data(),
                              w.peer.data() + d,
                              w.peer.data() + e,
                              w.shares[g.gate.left].data(),
                              w.shares[g.gate.right].data(),
                              t,
                              t + width,
                              t + 2 * width,
                              width,
                              !server,
                              g.gate.op == '|'};
        };
        for (const auto& g : layer) {
            if (g.gate.op == '!') {
                const auto& in = w.shares[g.gate.left];
                auto& out = w.shares[g.output];
                for (std::size_t i = 0; i < width; ++i)
                    out[i] = server ? in[i] : Byte(~in[i]);
                clear_tail(out, n);
            } else
                kernel(arguments(g, index++), false);
        }
        if (!count) {
            local_ms += ms(tick);
            continue;
        }
        const auto size = 2 * width * count;
        const bool record = layout == "record";
        if (record)
            for (std::size_t j = 0; j < width; ++j)
                for (unsigned i = 0; i < 2 * count; ++i)
                    w.transposed[j * 2 * count + i] = w.local[i * width + j];
        local_ms += ms(tick);
        const auto outgoing = std::span(record ? w.transposed : w.local).first(size);
        if (!server)
            tcp.send(20, level, outgoing);
        if (record) {

            tcp.receive_into(20, level, std::span(w.peer).first(size));
            if (server)
                tcp.send(20, level, outgoing);
            tick = Clock::now();
            for (std::size_t j = 0; j < width; ++j)
                for (unsigned i = 0; i < 2 * count; ++i)
                    w.transposed[i * width + j] = w.peer[j * 2 * count + i];
            std::swap(w.transposed, w.peer);
        } else {
            tcp.receive_into(20, level, std::span(w.peer).first(size));
            if (server)
                tcp.send(20, level, outgoing);
            tick = Clock::now();
        }
        ++rounds;
        index = 0;
        for (const auto& g : layer)
            if (g.gate.op != '!')
                kernel(arguments(g, index++), true);
        local_ms += ms(tick);
    }
    return std::move(w.shares[f.output]);
}
}
