#include "bitmap.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 3)
        return 2;
    std::size_t n = std::stoull(argv[2]);
    std::vector<std::uint8_t> data((n + 7) / 8);
    std::ifstream input(argv[1], std::ios::binary);
    input.read(reinterpret_cast<char*>(data.data()), data.size());
    if (!input || input.peek() != EOF)
        return 3;
    const auto begin = std::chrono::steady_clock::now();
    auto rows = retrieval::decode_bitmap_rows(data, n);
    const auto stop = std::chrono::steady_clock::now();
    std::cout << std::setprecision(12) << "{\"index_extract_ms\":"
              << std::chrono::duration<double, std::milli>(stop - begin).count() << ",\"rows\":[";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        if (i)
            std::cout << ',';
        std::cout << rows[i];
    }
    std::cout << "]}\n";
}
