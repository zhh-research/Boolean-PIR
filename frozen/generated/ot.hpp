#pragma once

#include "match.hpp"

#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <macoro/sync_wait.h>

namespace pbm {
using osuCrypto::block;
using osuCrypto::BitVector;
using osuCrypto::PRNG;
using SeedPair = std::array<block, 2>;

class Ot {
    coproto::AsioSocket socket_;
    osuCrypto::IknpOtExtSender sender_;
    osuCrypto::IknpOtExtReceiver receiver_;
    PRNG rng_{osuCrypto::sysRandomSeed()};

  public:
    Ot(bool server, unsigned port)
        : socket_(coproto::asioConnect("127.0.0.1:" + std::to_string(port), server)) {}
    void initialize(bool server) {
        if (server)
            macoro::sync_wait(sender_.genBaseOts(rng_, socket_));
        else
            macoro::sync_wait(receiver_.genBaseOts(rng_, socket_));
        macoro::sync_wait(socket_.flush());
    }
    std::vector<SeedPair> send(std::size_t count) {
        std::vector<SeedPair> values(count);
        if (count)
            macoro::sync_wait(sender_.send(values, rng_, socket_));
        macoro::sync_wait(socket_.flush());
        return values;
    }
    std::vector<block> receive(const BitVector& choices) {
        std::vector<block> values(choices.size());
        if (choices.size())
            macoro::sync_wait(receiver_.receive(choices, values, rng_, socket_));
        macoro::sync_wait(socket_.flush());
        return values;
    }
    std::uint64_t sent() { return socket_.bytesSent(); }
    std::uint64_t received() { return socket_.bytesReceived(); }
};

inline void prg_into(block seed, Bytes& destination, std::size_t n) {
    PRNG prg(seed);
    prg.get(destination.data(), destination.size());
    clear_tail(destination, n);
}

struct RotStats {
    double total = 0, ot = 0, prg = 0, gamma = 0, eta = 0, mapping = 0;
    Word sent = 0, received = 0, framing = 0;
};

inline std::vector<Masks> rot_expand(Tcp& tcp, Ot& ot, bool server, unsigned col, std::size_t n,
                                     unsigned d, unsigned slots,
                                     const std::vector<std::uint32_t>& mapping, RotStats& stats) {
    const auto begin = Clock::now();
    const auto sent = tcp.sent + ot.sent(), received = tcp.received + ot.received();
    const auto framing = tcp.framing();
    const auto rot_count = std::size_t(d - 1) * slots;
    BitVector choices(rot_count);
    std::vector<SeedPair> pairs;
    std::vector<block> selected;
    if (rot_count) {
        if (server)
            pairs = ot.send(rot_count);
        else {
            random_bytes(choices.data(), choices.sizeBytes());
            selected = ot.receive(choices);
        }
    }
    stats.ot = ms(begin);
    const auto group_start = Clock::now();
    std::vector<std::vector<std::uint32_t>> groups;
    if (server) {
        groups.resize(d);
        for (unsigned j = 0; j < n; ++j)
            groups[mapping[j]].push_back(j);
    }
    stats.mapping = ms(group_start);
    Bytes g0(bytes(n)), gamma(bytes(n));
    std::vector<Masks> result;
    for (unsigned slot = 0; slot < slots; ++slot) {
        Bytes sum(bytes(n));
        Bytes r;
        bool h = false;
        if (!server) {
            r.resize(bytes(d));
            h = bit(random_bits(1), 0);
            if (h) {
                toggle(r, d - 1);
                std::fill(sum.begin(), sum.end(), 0xff);
                clear_tail(sum, n);
            }
        }
        for (unsigned i = 0; i + 1 < d; ++i) {
            const auto j = std::size_t(slot) * (d - 1) + i;
            const auto message = slot * d + i;
            if (server) {
                auto tick = Clock::now();
                prg_into(pairs[j][0], g0, n);
                prg_into(pairs[j][1], gamma, n);
                stats.prg += ms(tick);
                tick = Clock::now();
                xor_into(sum, g0);
                xor_into(gamma, g0);
                for (const auto row : groups[i])
                    toggle(gamma, row);
                stats.gamma += ms(tick);
                tcp.send(30, col, gamma, message);
            } else {
                gamma = tcp.receive(30, col, bytes(n), true, message);
                auto tick = Clock::now();
                prg_into(selected[j], g0, n);
                stats.prg += ms(tick);
                tick = Clock::now();
                xor_into(sum, g0);
                const bool a = choices[j];
                if (a)
                    xor_into(sum, gamma);
                if (a ^ h)
                    toggle(r, i);
                stats.gamma += ms(tick);
            }
        }
        if (server) {
            const auto tick = Clock::now();
            auto s = random_bits(n);
            xor_into(sum, s);
            stats.eta += ms(tick);
            tcp.send(31, col, sum, slot);
            result.push_back({{}, std::move(s)});
        } else {
            const auto eta = tcp.receive(31, col, bytes(n), true, slot);
            const auto tick = Clock::now();
            xor_into(sum, eta);
            stats.eta += ms(tick);
            result.push_back({std::move(r), std::move(sum)});
        }
    }
    stats.total = ms(begin);
    stats.sent = tcp.sent + ot.sent() - sent;
    stats.received = tcp.received + ot.received() - received;
    stats.framing = tcp.framing() - framing;
    return result;
}
}
