#pragma once

#include "ot.hpp"

#include <bit>
#include <cstring>
#include <functional>

namespace pbm {
inline unsigned next_prime(unsigned width) {
    for (unsigned p = width + 1;; ++p) {
        bool prime = p >= 2;
        for (unsigned d = 2; d * d <= p; ++d)
            if (p % d == 0) {
                prime = false;
                break;
            }
        if (prime)
            return p;
    }
}

struct EqGroup {
    std::size_t count, bit_start, item_start, table_start;
    unsigned width, prime;
};
struct EqLayout {
    std::vector<EqGroup> groups;
    std::size_t bits = 0, items = 0, tables = 0;
    void add(std::size_t count, unsigned width) {
        const unsigned prime = next_prime(width);
        groups.push_back({count, bits, items, tables, width, prime});
        bits += count * width;
        items += count;
        tables += count * prime;
    }
};
struct EqState {
    Bytes r, lookup;
    std::vector<std::uint16_t> a, mask;
};
inline EqState new_eq_state(const EqLayout& shape) {
    return {random_bits(shape.bits), Bytes(bytes(shape.tables)),
            std::vector<std::uint16_t>(shape.bits), std::vector<std::uint16_t>(shape.items)};
}

inline unsigned uniform(PRNG& rng, unsigned modulus) {
    const unsigned limit = (65536u / modulus) * modulus;
    unsigned x;
    do {
        x = rng.get<std::uint16_t>();
    } while (x >= limit);
    return x % modulus;
}

inline std::array<EqState, 2> dealer_eq(const EqLayout& shape) {
    std::array<EqState, 2> out{new_eq_state(shape), new_eq_state(shape)};
    out[0].lookup = random_bits(shape.tables);
    out[1].lookup = out[0].lookup;
    PRNG rng(osuCrypto::sysRandomSeed());
    for (const auto g : shape.groups) {
        const unsigned p = g.prime;
        for (std::size_t i = g.bit_start; i < g.bit_start + g.count * g.width; ++i) {
            out[1].a[i] = uniform(rng, p);
            out[0].a[i] = (p + (bit(out[0].r, i) ^ bit(out[1].r, i)) - out[1].a[i]) % p;
        }
        for (std::size_t j = 0; j < g.count; ++j) {
            const unsigned m0 = uniform(rng, p), m1 = uniform(rng, p);
            out[0].mask[g.item_start + j] = m0;
            out[1].mask[g.item_start + j] = m1;
            toggle(out[1].lookup, g.table_start + j * p + (m0 + m1) % p);
        }
    }
    return out;
}

inline std::vector<Bytes> online_eq(Tcp& tcp, bool server, const EqLayout& layout,
                                    const EqState& state, Bytes input, bool packed,
                                    std::vector<double>* local_times = nullptr,
                                    std::function<Bytes(const std::vector<Bytes>&)> correction = {},
                                    std::size_t correction_bytes = 0,
                                    Bytes* received_correction = nullptr) {
    xor_into(input, state.r);
    if (server)
        tcp.send(43, 0, input);
    const auto other = tcp.receive(43, 0, input.size());
    if (!server)
        tcp.send(43, 0, input);
    xor_into(input, other);
    std::size_t short_bits = 0;
    for (const auto g : layout.groups)
        short_bits += g.count * (packed ? std::bit_width(g.prime - 1) : (g.prime <= 256 ? 8 : 16));
    Bytes msg(bytes(short_bits));
    std::size_t offset = 0, column = 0;
    if (local_times)
        local_times->assign(layout.groups.size(), 0.0);
    for (const auto g : layout.groups) {
        const auto tick = Clock::now();
        const unsigned w = packed ? std::bit_width(g.prime - 1) : (g.prime <= 256 ? 8 : 16);
        for (std::size_t j = 0; j < g.count; ++j) {
            unsigned sum = state.mask[g.item_start + j];
            for (unsigned b = 0; b < g.width; ++b) {
                const auto i = g.bit_start + j * g.width + b;
                const unsigned a = state.a[i];
                sum += bit(input, i) ? (g.prime - a + server) : a;
            }
            sum %= g.prime;
            for (unsigned b = 0; b < w; ++b)
                if ((sum >> b) & 1)
                    toggle(msg, offset + b);
            offset += w;
        }
        if (local_times)
            (*local_times)[column++] += ms(tick);
    }
    const bool fused = correction_bytes != 0;
    if ((!fused && !server) || (fused && server))
        tcp.send(44, 0, msg);
    auto peer = tcp.receive(44, 0, msg.size() + (fused && server ? correction_bytes : 0));
    if (!fused && server)
        tcp.send(44, 0, msg);
    if (fused && server) {
        require(received_correction != nullptr, "Missing correction sink");
        received_correction->assign(peer.begin() + msg.size(), peer.end());
    }
    offset = 0;
    std::vector<Bytes> results;
    column = 0;
    for (const auto g : layout.groups) {
        const auto tick = Clock::now();
        const unsigned w = packed ? std::bit_width(g.prime - 1) : (g.prime <= 256 ? 8 : 16);
        auto& result = results.emplace_back(bytes(g.count));
        for (std::size_t j = 0; j < g.count; ++j) {
            unsigned a = 0, b = 0;
            for (unsigned k = 0; k < w; ++k) {
                a |= unsigned(bit(msg, offset + k)) << k;
                b |= unsigned(bit(peer, offset + k)) << k;
            }
            require(b < g.prime, "Noncanonical short equality input");
            if (bit(state.lookup, g.table_start + j * g.prime + (a + b) % g.prime))
                toggle(result, j);
            offset += w;
        }
        if (local_times)
            (*local_times)[column++] += ms(tick);
    }
    if (fused && !server) {
        const auto tail = correction(results);
        require(tail.size() == correction_bytes, "Wrong fused correction size");
        msg.insert(msg.end(), tail.begin(), tail.end());
        tcp.send(44, 0, msg);
    }
    return results;
}
}
