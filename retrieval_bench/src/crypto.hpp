#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace retrieval {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using View = std::span<const Byte>;
using Point = std::array<Byte, 32>;
using Scalar = std::array<Byte, 32>;
using Prf = std::array<Byte, 64>;
using Key = std::array<Byte, 32>;

struct Blind {
    Scalar scalar;
    Scalar inverse;
};

struct DatabaseId {
    std::array<Byte, 16> id;
    std::uint64_t version;
    DatabaseId(const std::string& hex, std::uint64_t version);
    Bytes input(std::uint64_t row, bool dummy = false) const;
    Bytes aad(std::uint64_t row) const;
    Key salt;
};

void check(bool ok, const char* message);
Bytes unhex(const std::string& s);
void append64(Bytes& data, std::uint64_t value);
Scalar random_scalar();
void validate_scalar(const Scalar& scalar);
Blind prepare_blind();
Point blind(View input, const Scalar& scalar);
Point evaluate_point(const Scalar& key, const Point& point);
Prf finalize(View input, const Scalar& inverse, const Point& point);
Prf evaluate(const Scalar& key, View input);
Key derive_key(const Prf& prf, const DatabaseId& db, std::uint64_t row);
Bytes encrypt(View plaintext, const Key& key, View aad);
Bytes decrypt(View record, const Key& key, View aad);
class CryptoWorkerContext {
  public:
    CryptoWorkerContext();
    ~CryptoWorkerContext();
    CryptoWorkerContext(const CryptoWorkerContext&) = delete;
    CryptoWorkerContext& operator=(const CryptoWorkerContext&) = delete;
    Key derive_key(const Prf&, const DatabaseId&, std::uint64_t row);
    Bytes decrypt(View record, const Key&, View aad);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
