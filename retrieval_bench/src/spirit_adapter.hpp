#pragma once
#include "crypto.hpp"
#include "spirit_overlay.hpp"
#include <filesystem>
#include <memory>
#include <string>

namespace retrieval {
namespace pir = spirit::pir;
namespace fs = std::filesystem;

struct Shape {
    std::size_t n, length, capacity;
    std::size_t pbc_capacity() const { return capacity == 1 ? 2 : capacity; }
    std::size_t buckets() const { return 3 * pbc_capacity() / 2; }
    std::size_t record() const { return length + 28; }
    pir::BatchParams params() const;
    std::uint64_t minimum_bytes() const;
};

struct Public {
    pir::BatchPublicParams params;
    explicit Public(const Shape& shape, const fs::path& file);
};

struct PirClientTiming {
    double bind_ms{}, query_serialize_ms{}, response_deserialize_ms{}, extract_ms{};
};

struct PirServerTiming {
    double request_deserialize_ms{}, query_precompute_ms{}, answer_compute_ms{},
        response_serialize_ms{};
};

struct ClientPir {
    const pir::BatchPublicParams& pp;
    seal::SEALContext context;
    seal::KeyGenerator keygen;
    seal::SecretKey key;
    seal::Encryptor encryptor;
    seal::Evaluator evaluator;
    seal::Decryptor decryptor;
    std::vector<std::unique_ptr<seal::Decryptor>> workers;
    pir::BatchQueryMessage query;
    pir::BatchClientState state;
    explicit ClientPir(const Public& setup, unsigned extract_threads = 0);
    std::string make_query(const std::vector<std::size_t>& rows, PirClientTiming& timing);
    pir::BatchResponseMessage deserialize(std::string wire);
    std::vector<Bytes> extract(const pir::BatchResponseMessage& response, bool parallel);
    int minimum_noise_budget(const pir::BatchResponseMessage& response);
};

struct ServerPir {
    pir::BatchPublicParams pp;
    pir::BatchServerState state;
    pir::BatchAnswerPrecompState prepared;
    seal::SEALContext context;
    seal::Evaluator evaluator;
    ServerPir();
    void setup(const Shape& shape, const fs::path& encrypted, const fs::path& public_file);
    void save(const fs::path& aux) const;
    void load(const Shape& shape, const fs::path& public_file, const fs::path& aux);
    void prepare();
    std::string answer(std::string request, PirServerTiming& timing);
};

void read_exact(std::istream& in, void* data, std::size_t bytes);
void write_exact(std::ostream& out, const void* data, std::size_t bytes);
}
