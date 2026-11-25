#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace retrieval {
inline std::vector<std::size_t> decode_bitmap_rows(const std::vector<std::uint8_t>& data,
                                                   std::size_t n) {
    std::vector<std::size_t> rows;
    for (std::size_t i = 0; i < n; ++i)
        if ((data[i / 8] >> (i % 8)) & 1)
            rows.push_back(i);
    return rows;
}
}
