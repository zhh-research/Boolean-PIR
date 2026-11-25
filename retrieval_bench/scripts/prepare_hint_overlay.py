import argparse
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("upstream", type=Path)
p.add_argument("output", type=Path)
a = p.parse_args()
original = (a.upstream / "src/SPIRIT/pir/public_matrix.cpp").read_text()
signature = "    void compute_hint_matrix_from_seed("
if original.count(signature) != 1:
    raise RuntimeError("Unexpected upstream hint implementation")
source = original.replace(signature, "    static void compute_hint_rows(")
source = "#include <algorithm>\n" + source
source += """
namespace spirit::pir {
    void compute_hint_matrix_from_seed(
        const std::vector<uint64_t> &database,
        size_t rows,
        size_t cols,
        const seal::prng_seed_type &seed,
        size_t lwe_dimension,
        std::vector<uint32_t> &hint)
    {
        if (database.size() != rows * cols)
            throw std::invalid_argument("database size must equal rows * cols");
        constexpr size_t tile_rows = 128;
        if (rows <= tile_rows)
        {
            compute_hint_rows(database, rows, cols, seed, lwe_dimension, hint);
            return;
        }
        hint.resize(rows * lwe_dimension);
        std::vector<uint32_t> tile_hint;
        for (size_t first = 0; first < rows; first += tile_rows)
        {
            const auto count = std::min(tile_rows, rows - first);
            const auto start = database.begin() + first * cols;
            const std::vector<uint64_t> tile(start, start + count * cols);
            compute_hint_rows(tile, count, cols, seed, lwe_dimension, tile_hint);
            std::copy(tile_hint.begin(), tile_hint.end(), hint.begin() + first * lwe_dimension);
        }
    }


}
"""
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(source)
