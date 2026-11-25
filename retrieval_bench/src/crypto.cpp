#include "crypto.hpp"
#include <algorithm>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <sodium.h>
#include <stdexcept>
#include <string_view>

namespace retrieval {
namespace {
constexpr char dst_bytes[] = "HashToGroup-OPRFV1-\0-ristretto255-SHA512";
constexpr std::string_view dst{dst_bytes, sizeof(dst_bytes) - 1};
constexpr std::string_view salt_label = "PBM-Retrieval-HKDF-Salt-v1";
constexpr std::string_view key_label = "PBM-Retrieval-AES256-GCM-Key-v1";
constexpr std::string_view aad_label = "PBM-Payload-AEAD-v1";
constexpr std::size_t nonce_size = 12, tag_size = 16;

void append(Bytes& out, View in) { out.insert(out.end(), in.begin(), in.end()); }
void append(Bytes& out, std::string_view in) { out.insert(out.end(), in.begin(), in.end()); }
void append16(Bytes& out, std::size_t n) {
    check(n <= 65535, "OPRF input exceeds RFC 9497 length bound");
    out.push_back(n >> 8);
    out.push_back(n);
}

Prf sha512(View data) {
    Prf out{};
    check(SHA512(data.data(), data.size(), out.data()) != nullptr, "SHA-512 failed");
    return out;
}

Point hash_to_group(View input) {

    Bytes seed(128, 0);
    append(seed, input);
    append16(seed, 64);
    seed.push_back(0);
    append(seed, dst);
    seed.push_back(dst.size());
    auto b0 = sha512(seed);
    Bytes block(b0.begin(), b0.end());
    block.push_back(1);
    append(block, dst);
    block.push_back(dst.size());
    auto uniform = sha512(block);
    Point p{};
    check(crypto_core_ristretto255_from_hash(p.data(), uniform.data()) == 0,
          "Ristretto255 map failed");
    return p;
}

Point multiply(const Scalar& k, const Point& p) {
    Point result{};
    check(crypto_scalarmult_ristretto255(result.data(), k.data(), p.data()) == 0,
          "Ristretto255 scalar multiplication failed");
    return result;
}

void validate_point(const Point& p) {
    check(crypto_core_ristretto255_is_valid_point(p.data()) == 1 &&
              sodium_is_zero(p.data(), p.size()) == 0,
          "Invalid or identity Ristretto255 point");
}

Prf hash_output(View input, const Point& point) {
    Bytes buf;
    buf.reserve(4 + input.size() + point.size() + 8);
    append16(buf, input.size());
    append(buf, input);
    append16(buf, point.size());
    append(buf, point);
    append(buf, "Finalize");
    return sha512(buf);
}

using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
Cipher new_cipher() {
    Cipher ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    check(bool(ctx), "EVP_CIPHER_CTX allocation failed");
    return ctx;
}

template <std::size_t N> std::array<Byte, N> from_hex(const std::string& s) {
    auto b = unhex(s);
    check(b.size() == N, "Unexpected encoded length");
    std::array<Byte, N> a{};
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}
}

void check(bool ok, const char* message) {
    if (!ok)
        throw std::runtime_error(message);
}

Bytes unhex(const std::string& s) {
    check(s.size() % 2 == 0, "Odd hex encoding");
    Bytes out(s.size() / 2);
    std::size_t size = 0;
    check(sodium_hex2bin(out.data(), out.size(), s.data(), s.size(), nullptr, &size, nullptr) ==
                  0 &&
              size == out.size(),
          "Invalid hex encoding");
    return out;
}

void append64(Bytes& data, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        data.push_back(value >> shift);
}

DatabaseId::DatabaseId(const std::string& hex, std::uint64_t v)
    : id(from_hex<16>(hex)), version(v) {
    Bytes context;
    append(context, salt_label);
    append(context, id);
    append64(context, version);
    check(SHA256(context.data(), context.size(), salt.data()) != nullptr, "SHA-256 failed");
}

Bytes DatabaseId::input(std::uint64_t row, bool dummy) const {
    Bytes buf;
    buf.reserve(33);
    buf.push_back(dummy ? 2 : 1);
    append(buf, id);
    append64(buf, version);
    append64(buf, row);
    return buf;
}

Bytes DatabaseId::aad(std::uint64_t row) const {
    Bytes buf;
    append(buf, aad_label);
    append(buf, id);
    append64(buf, version);
    append64(buf, row);
    return buf;
}

Scalar random_scalar() {
    Scalar s{};
    do {
        crypto_core_ristretto255_scalar_random(s.data());
    } while (sodium_is_zero(s.data(), s.size()));
    return s;
}

void validate_scalar(const Scalar& scalar) {
    std::array<Byte, 64> wide{};
    std::copy(scalar.begin(), scalar.end(), wide.begin());
    Scalar reduced{};
    crypto_core_ristretto255_scalar_reduce(reduced.data(), wide.data());
    check(sodium_memcmp(reduced.data(), scalar.data(), scalar.size()) == 0 &&
              sodium_is_zero(scalar.data(), scalar.size()) == 0,
          "Invalid OPRF key encoding");
}

Blind prepare_blind() {
    Blind b{};
    b.scalar = random_scalar();
    check(crypto_core_ristretto255_scalar_invert(b.inverse.data(), b.scalar.data()) == 0,
          "OPRF blind inversion failed");
    return b;
}

Point blind(View input, const Scalar& scalar) { return multiply(scalar, hash_to_group(input)); }
Point evaluate_point(const Scalar& key, const Point& point) {
    validate_point(point);
    return multiply(key, point);
}
Prf finalize(View input, const Scalar& inverse, const Point& point) {
    validate_point(point);
    return hash_output(input, multiply(inverse, point));
}
Prf evaluate(const Scalar& key, View input) {
    return hash_output(input, multiply(key, hash_to_group(input)));
}

namespace {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
using Kdf = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
Kdf new_kdf() {
    static const std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> hkdf(
        EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    check(bool(hkdf), "HKDF provider unavailable");
    Kdf ctx(EVP_KDF_CTX_new(hkdf.get()), EVP_KDF_CTX_free);
    check(bool(ctx), "HKDF context allocation failed");
    return ctx;
}
#else
using Kdf = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
Kdf new_kdf() {
    Kdf ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    check(bool(ctx), "HKDF context allocation failed");
    return ctx;
}
#endif

Key derive_with(const Kdf& ctx, const Prf& prf, const DatabaseId& db, std::uint64_t row) {
    Bytes info;
    append(info, key_label);
    append64(info, row);
    Key k{};
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char digest[] = "SHA256";
    OSSL_PARAM params[]{
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<Byte*>(prf.data()),
                                          prf.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<Byte*>(db.salt.data()),
                                          db.salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
        OSSL_PARAM_construct_end()};
    check(ctx && EVP_KDF_derive(ctx.get(), k.data(), k.size(), params) == 1, "HKDF-SHA256 failed");
#else
    auto size = k.size();
    check(ctx && EVP_PKEY_derive_init(ctx.get()) > 0 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), db.salt.data(), db.salt.size()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), prf.data(), prf.size()) > 0 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), info.size()) > 0 &&
              EVP_PKEY_derive(ctx.get(), k.data(), &size) > 0 && size == k.size(),
          "HKDF-SHA256 failed");
#endif
    return k;
}
}

Key derive_key(const Prf& prf, const DatabaseId& db, std::uint64_t row) {
    return derive_with(new_kdf(), prf, db, row);
}

Bytes encrypt(View plaintext, const Key& key, View aad) {
    auto ctx = new_cipher();
    Bytes out(nonce_size + plaintext.size() + tag_size);
    randombytes_buf(out.data(), nonce_size);
    int len = 0, last = 0;
    check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), out.data()) == 1 &&
              EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_EncryptUpdate(ctx.get(), out.data() + nonce_size, &len, plaintext.data(),
                                plaintext.size()) == 1 &&
              EVP_EncryptFinal_ex(ctx.get(), out.data() + nonce_size + len, &last) == 1 &&
              std::size_t(len + last) == plaintext.size() &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size,
                                  out.data() + nonce_size + len) == 1,
          "AES-256-GCM encrypt failed");
    return out;
}

namespace {
Bytes decrypt_with(const Cipher& ctx, View record, const Key& key, View aad) {
    check(record.size() >= nonce_size + tag_size, "Encrypted record too short");
    const auto length = record.size() - nonce_size - tag_size;
    Bytes out(length);
    int len = 0, last = 0;
    check(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), record.data()) ==
                  1 &&
              EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()) == 1 &&
              EVP_DecryptUpdate(ctx.get(), out.data(), &len, record.data() + nonce_size, length) ==
                  1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size,
                                  const_cast<Byte*>(record.data() + nonce_size + length)) == 1 &&
              EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &last) == 1 &&
              std::size_t(len + last) == length,
          "AES-256-GCM authentication failed");
    return out;
}
}

Bytes decrypt(View record, const Key& key, View aad) {
    return decrypt_with(new_cipher(), record, key, aad);
}

struct CryptoWorkerContext::Impl {
    Kdf kdf = new_kdf();
    Cipher cipher = new_cipher();
};
CryptoWorkerContext::CryptoWorkerContext() : impl_(std::make_unique<Impl>()) {}
CryptoWorkerContext::~CryptoWorkerContext() = default;

Key CryptoWorkerContext::derive_key(const Prf& prf, const DatabaseId& db, std::uint64_t row) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_KDF_CTX_reset(impl_->kdf.get());
#endif
    return derive_with(impl_->kdf, prf, db, row);
}

Bytes CryptoWorkerContext::decrypt(View record, const Key& key, View aad) {
    check(EVP_CIPHER_CTX_reset(impl_->cipher.get()) == 1, "AES-GCM context reset failed");
    return decrypt_with(impl_->cipher, record, key, aad);
}

}
