#pragma once

#include "core.hpp"

#include <unordered_map>

namespace pbm {
struct Domain {
    std::vector<Word> values;
    std::vector<std::uint32_t> map;
};

inline Domain domain(const std::vector<Word>& database, unsigned col, std::size_t n, unsigned width,
                     std::size_t expected) {
    Domain result;
    result.values.reserve(expected);
    result.map.reserve(n);
    std::unordered_map<Word, std::uint32_t> seen;
    seen.reserve(expected);
    for (std::size_t j = 0; j < n; ++j) {
        const auto value = database[col * n + j];
        require(width == 64 || value < (Word(1) << width), "Database value exceeds encoding width");
        const auto [entry, added] = seen.try_emplace(value, result.values.size());
        if (added)
            result.values.push_back(value);
        result.map.push_back(entry->second);
    }
    require(result.values.size() == expected, "Database domain does not match public size");
    return result;
}

struct Masks {
    Bytes r, row;
};
inline Bytes expand(Tcp& tcp, bool server, unsigned col, Bytes eq, Masks mask,
                    const std::vector<std::uint32_t>& mapping, std::size_t d) {
    if (server) {
        const Bytes delta = tcp.receive(10, col, bytes(d));
        xor_into(eq, delta);
        for (std::size_t j = 0; j < mapping.size(); ++j)
            if (bit(eq, mapping[j]))
                toggle(mask.row, j);
    } else {
        xor_into(eq, mask.r);
        tcp.send(10, col, eq);
    }
    return std::move(mask.row);
}

struct Triple {
    Bytes a, b, c;
};
inline Bytes boolean_tree(Tcp& tcp, bool server, const Formula& formula, std::vector<Bytes> inputs,
                          const std::vector<Triple>& triples, std::size_t n, unsigned& rounds) {
    const auto width = bytes(n), k = inputs.size();
    inputs.resize(k + formula.gates.size());
    for (unsigned level = 1; level <= formula.depth; ++level) {
        std::vector<unsigned> batch;
        Bytes local;
        unsigned triple_index = 0;
        for (unsigned i = 0; i < formula.gates.size(); ++i) {
            const auto gate = formula.gates[i];
            if (gate.op == '!') {
                if (gate.level == level) {
                    inputs[k + i] = inputs[gate.left];
                    if (!server) {
                        for (auto& value : inputs[k + i])
                            value = ~value;
                        clear_tail(inputs[k + i], n);
                    }
                }
                continue;
            }
            if (gate.level == level) {
                batch.push_back(i);
                const auto& t = triples[triple_index];
                for (std::size_t j = 0; j < width; ++j)
                    local.push_back(inputs[gate.left][j] ^ t.a[j]);
                for (std::size_t j = 0; j < width; ++j)
                    local.push_back(inputs[gate.right][j] ^ t.b[j]);
            }
            ++triple_index;
        }
        if (batch.empty())
            continue;
        ++rounds;
        if (!server)
            tcp.send(20, level, local);
        const Bytes other = tcp.receive(20, level, local.size());
        if (server)
            tcp.send(20, level, local);
        xor_into(local, other);
        std::size_t offset = 0;
        triple_index = 0;
        for (unsigned i = 0; i < formula.gates.size(); ++i) {
            const auto gate = formula.gates[i];
            if (gate.op == '!')
                continue;
            const auto& t = triples[triple_index++];
            if (gate.level != level)
                continue;
            auto& output = inputs[k + i];
            output.resize(width);
            for (std::size_t j = 0; j < width; ++j) {
                const Byte d = local[offset + j], e = local[offset + width + j];
                output[j] = t.c[j] ^ (d & t.b[j]) ^ (e & t.a[j]);
                if (!server)
                    output[j] ^= d & e;
                if (gate.op == '|')
                    output[j] ^= inputs[gate.left][j] ^ inputs[gate.right][j];
            }
            offset += 2 * width;
        }
    }
    return std::move(inputs[formula.output]);
}

}
