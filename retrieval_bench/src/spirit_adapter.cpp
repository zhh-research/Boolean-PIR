#include "spirit_adapter.hpp"

#include <bit>
#include <chrono>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>

namespace retrieval {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t lwe = 1024, degree = 2048;
static_assert(std::endian::native == std::endian::little);

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

seal::EncryptionParameters spirit_params() {
    seal::EncryptionParameters p(seal::scheme_type::bfv);
    p.set_poly_modulus_degree(degree);
    p.set_coeff_modulus(seal::CoeffModulus::Create(degree, {56, 60}));
    p.set_plain_modulus(65537);
    return p;
}

void put(std::ostream& out, std::uint64_t x) { write_exact(out, &x, sizeof(x)); }
std::uint64_t get(std::istream& in) {
    std::uint64_t x{};
    read_exact(in, &x, sizeof(x));
    return x;
}

template <class T> void write_vector(std::ostream& out, const std::vector<T>& data) {
    put(out, data.size());
    write_exact(out, data.data(), data.size() * sizeof(T));
}

template <class T> void read_vector(std::istream& in, std::vector<T>& data, std::size_t max_items) {
    const auto n = get(in);
    check(n <= max_items, "Invalid packed vector length");
    data.resize(n);
    read_exact(in, data.data(), data.size() * sizeof(T));
}

void end(std::istream& stream) {
    check(stream.peek() == EOF && !stream.bad(), "Trailing state or message bytes");
}

void write_public(const Shape& shape, const pir::BatchPublicParams& pp, const fs::path& file) {
    std::ofstream f(file, std::ios::binary | std::ios::trunc);
    put(f, 0x53505001);
    put(f, shape.n);
    put(f, shape.record());
    put(f, shape.pbc_capacity());
    put(f, pp.pbc_public_params.num_buckets);
    for (std::size_t b = 0; b < pp.bucket_layouts.size(); ++b) {
        const auto& l = pp.bucket_layouts[b];
        put(f, l.item_slots);
        put(f, l.items_per_column);
        put(f, l.rows);
        put(f, l.cols);
        const auto& seed = pp.bucket_public_params[b].public_matrix_seed;
        write_exact(f, seed.data(), sizeof(seed));
    }
    f.close();
    check(bool(f), "Public parameter write failed");
}

std::string query_wire(const pir::BatchQueryMessage& q) {
    std::ostringstream out(std::ios::binary);

    for (const auto& b : q.bucket_queries)
        write_exact(out, b.query_vector.data(), b.query_vector.size() * sizeof(std::uint32_t));
    q.packed_secret.save(out, seal::compr_mode_type::none);
    q.galois_keys.save(out, seal::compr_mode_type::none);
    return std::move(out).str();
}

pir::BatchQueryMessage read_query(const pir::BatchPublicParams& pp,
                                  const seal::SEALContext& context, std::string wire) {
    std::istringstream in(std::move(wire), std::ios::binary);
    pir::BatchQueryMessage q;
    q.bucket_queries.resize(pp.bucket_layouts.size());
    for (std::size_t b = 0; b < q.bucket_queries.size(); ++b) {
        auto& bucket = q.bucket_queries[b];
        bucket.bucket_index = b;
        bucket.query_vector.resize(pp.bucket_layouts[b].cols);
        read_exact(in, bucket.query_vector.data(),
                   bucket.query_vector.size() * sizeof(std::uint32_t));
    }
    q.packed_secret.load(context, in);
    q.galois_keys.load(context, in);
    end(in);
    return q;
}

std::string response_wire(const pir::BatchResponseMessage& response) {
    std::ostringstream out(std::ios::binary);
    for (const auto& b : response.bucket_responses)
        for (const auto& c : b.packed_columns)
            c.save(out, seal::compr_mode_type::none);
    return std::move(out).str();
}

pir::BatchResponseMessage read_response(const pir::BatchPublicParams& pp,
                                        const seal::SEALContext& context, std::string wire) {
    std::istringstream in(std::move(wire), std::ios::binary);
    pir::BatchResponseMessage response;
    response.bucket_responses.resize(pp.bucket_layouts.size());
    for (std::size_t b = 0; b < response.bucket_responses.size(); ++b) {
        auto& bucket = response.bucket_responses[b];
        bucket.bucket_index = b;
        bucket.packed_columns.resize((pp.bucket_layouts[b].rows + degree - 1) / degree);
        for (auto& c : bucket.packed_columns)
            c.load(context, in);
    }
    end(in);
    return response;
}
}

void read_exact(std::istream& in, void* data, std::size_t bytes) {
    if (bytes != 0)
        in.read(static_cast<char*>(data), bytes);
    check(bool(in), "Short read or file open failed");
}
void write_exact(std::ostream& out, const void* data, std::size_t bytes) {
    if (bytes != 0)
        out.write(static_cast<const char*>(data), bytes);
    check(bool(out), "Write failed");
}

pir::BatchParams Shape::params() const {
    pir::BatchParams p;
    p.pbc_params.num_entries = n;
    p.pbc_params.batch_size = pbc_capacity();
    p.pbc_params.cuckoo_factor = 1.5;
    p.lwe_dimension = lwe;
    p.record_plain_modulus = 256;
    p.record_size_bytes = record();
    return p;
}

std::uint64_t Shape::minimum_bytes() const {

    const auto chunks = (record() + degree - 1) / degree;
    return 3ULL * n * record() * sizeof(std::uint64_t) + 8ULL * buckets() * chunks * lwe * degree;
}

Public::Public(const Shape& shape, const fs::path& file) {
    std::ifstream f(file, std::ios::binary);
    check(get(f) == 0x53505001 && get(f) == shape.n && get(f) == shape.record() &&
              get(f) == shape.pbc_capacity() && get(f) == shape.buckets(),
          "Public parameters do not match shape");
    params.params = shape.params();
    std::vector<std::uint64_t> rows(shape.n);
    std::iota(rows.begin(), rows.end(), 0);
    pir::PBCServerState scratch;
    pir::BuildPBCBuckets(rows, params.params.pbc_params, params.pbc_public_params, scratch);
    params.bucket_layouts.resize(shape.buckets());
    params.bucket_public_params.resize(shape.buckets());
    for (std::size_t b = 0; b < shape.buckets(); ++b) {
        auto& l = params.bucket_layouts[b];
        l.item_slots = get(f);
        l.items_per_column = get(f);
        l.rows = get(f);
        l.cols = get(f);
        l.record_size_bytes = shape.record();
        check(l.item_slots == scratch.actual_bucket_sizes[b] && l.items_per_column >= 1 &&
                  l.items_per_column <= std::max<std::size_t>(1, l.item_slots) &&
                  l.rows == l.items_per_column * shape.record() &&
                  l.cols == std::max<std::size_t>(1, (l.item_slots + l.items_per_column - 1) /
                                                         l.items_per_column),
              "Public bucket layout is invalid");
        l.item_layouts.resize(l.item_slots);
        for (std::size_t i = 0; i < l.item_slots; ++i)
            l.item_layouts[i] = {i / l.items_per_column, (i % l.items_per_column) * shape.record()};
        auto& bucket = params.bucket_public_params[b];
        bucket.params = {l.rows, l.cols, lwe, 256, false};
        read_exact(f, bucket.public_matrix_seed.data(), sizeof(bucket.public_matrix_seed));
    }
    end(f);
}

ClientPir::ClientPir(const Public& setup, unsigned extract_threads)
    : pp(setup.params), context(spirit_params()), keygen(context), key(keygen.secret_key()),
      encryptor(context, key), evaluator(context), decryptor(context, key) {
    pir::PrepareBatchQuery(pp, context, keygen, encryptor, evaluator, query, state);
    workers.reserve(extract_threads);
    for (unsigned i = 0; i < extract_threads; ++i)
        workers.push_back(std::make_unique<seal::Decryptor>(context, key));
}

std::string ClientPir::make_query(const std::vector<std::size_t>& rows, PirClientTiming& timing) {
    const auto bind = Clock::now();
    pir::BindBatchQuery(pp, rows, query, state);
    timing.bind_ms = elapsed(bind);
    const auto encode = Clock::now();
    auto wire = query_wire(query);
    timing.query_serialize_ms = elapsed(encode);
    return wire;
}

pir::BatchResponseMessage ClientPir::deserialize(std::string wire) {
    return read_response(pp, context, std::move(wire));
}

std::vector<Bytes> ClientPir::extract(const pir::BatchResponseMessage& response, bool parallel) {
    std::vector<Bytes> records;
    if (parallel)
        pir::BatchExtractParallel(pp, state, response, context, workers, records);
    else
        pir::BatchExtract(pp, state, response, context, decryptor, records);
    return records;
}

int ClientPir::minimum_noise_budget(const pir::BatchResponseMessage& response) {
    int minimum = std::numeric_limits<int>::max();
    for (const auto& b : response.bucket_responses)
        for (const auto& c : b.packed_columns)
            minimum = std::min(minimum, decryptor.invariant_noise_budget(c));
    return minimum;
}

ServerPir::ServerPir() : context(spirit_params()), evaluator(context) {}

void ServerPir::setup(const Shape& shape, const fs::path& encrypted, const fs::path& public_file) {
    check(fs::file_size(encrypted) == shape.n * shape.record(), "Encrypted database size mismatch");
    std::ifstream f(encrypted, std::ios::binary);
    std::vector<Bytes> records(shape.n, Bytes(shape.record()));
    for (auto& row : records)
        read_exact(f, row.data(), row.size());
    pir::BatchDBSetup(records, shape.params(), pp, state);
    write_public(shape, pp, public_file);
}

void ServerPir::save(const fs::path& aux) const {
    std::ofstream out(aux, std::ios::binary | std::ios::trunc);
    put(out, 0x53504101);
    put(out, state.bucket_server_states.size());
    for (const auto& b : state.bucket_server_states) {
        const auto& packed = b.packed_database;
        put(out, packed.rows);
        put(out, packed.cols);
        put(out, packed.padded_rows);
        put(out, packed.padded_cols);
        put(out, packed.packed_cols);
        write_vector(out, packed.data);
        write_vector(out, b.hint_matrix);

        if (packed.empty())
            write_vector(out, b.database);
    }
    out.close();
    check(bool(out), "SPIRIT aux write failed");
}

void ServerPir::load(const Shape& shape, const fs::path& public_file, const fs::path& aux) {
    pp = Public(shape, public_file).params;
    std::ifstream in(aux, std::ios::binary);
    check(get(in) == 0x53504101 && get(in) == pp.bucket_layouts.size(),
          "SPIRIT aux shape mismatch");
    state.bucket_server_states.resize(pp.bucket_layouts.size());
    for (std::size_t i = 0; i < state.bucket_server_states.size(); ++i) {
        auto& b = state.bucket_server_states[i];
        const auto& layout = pp.bucket_layouts[i];
        auto& packed = b.packed_database;
        packed.rows = get(in);
        packed.cols = get(in);
        packed.padded_rows = get(in);
        packed.padded_cols = get(in);
        packed.packed_cols = get(in);
        const auto matrix_size = layout.rows * layout.cols;
        read_vector(in, packed.data, (layout.rows + 64) * (layout.cols + 64));
        read_vector(in, b.hint_matrix, layout.rows * lwe);
        check(b.hint_matrix.size() == layout.rows * lwe, "SPIRIT hint shape mismatch");
        if (packed.empty()) {
            read_vector(in, b.database, matrix_size);
            check(b.database.size() == matrix_size, "SPIRIT matrix shape mismatch");
        } else {
            check(packed.rows == layout.rows && packed.cols == layout.cols &&
                      packed.padded_rows <= layout.rows + 64 &&
                      packed.padded_cols <= layout.cols + 64 &&
                      packed.packed_cols <= packed.padded_cols &&
                      packed.data.size() == packed.padded_rows * packed.packed_cols,
                  "SPIRIT packed matrix shape mismatch");
        }
    }
    end(in);
}

void ServerPir::prepare() { pir::BatchAnswerPrecompute(pp, state, context, evaluator, prepared); }

std::string ServerPir::answer(std::string request, PirServerTiming& timing) {
    auto start = Clock::now();
    auto query = read_query(pp, context, std::move(request));
    timing.request_deserialize_ms = elapsed(start);
    pir::BatchQueryAnswerPrecompState per_query;
    pir::BatchResponseMessage response;
    start = Clock::now();
    pir::BatchAnswerQueryPrecompute(pp, prepared, query, context, evaluator, per_query);
    timing.query_precompute_ms = elapsed(start);
    start = Clock::now();
    pir::AnswerWithoutSecret(pp, state, prepared, per_query, query, context, evaluator, response);
    timing.answer_compute_ms = elapsed(start);
    start = Clock::now();
    auto wire = response_wire(response);
    timing.response_serialize_ms = elapsed(start);
    return wire;
}

}
