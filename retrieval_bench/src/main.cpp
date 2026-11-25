#include "bitmap.hpp"
#include "spirit_adapter.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <numeric>
#include <optional>
#include <sodium.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unordered_set>
#include <unistd.h>
#include <utility>

namespace retrieval {
namespace {
using Clock = std::chrono::steady_clock;
constexpr char default_db_id[] = "50424d2d52455452494556414c2d3031";

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::uint64_t number(std::string_view s) {
    std::uint64_t n{};
    const auto result = std::from_chars(s.data(), s.data() + s.size(), n);
    check(result.ec == std::errc{} && result.ptr == s.data() + s.size(),
          "Invalid unsigned integer");
    return n;
}

struct Args {
    std::string action;
    std::map<std::string, std::string> args;
    Args(int argc, char** argv) {
        check(argc >= 2 && argc % 2 == 0, "Usage: retrieval ACTION --key value ...");
        action = argv[1];
        for (int i = 2; i < argc; i += 2) {
            std::string key = argv[i];
            check(key.starts_with("--") && args.emplace(key.substr(2), argv[i + 1]).second,
                  "Invalid or duplicate option");
        }
    }
    std::string opt(const std::string& k, std::string fallback = {}) const {
        const auto found = args.find(k);
        return found != args.end() ? found->second : fallback;
    }
    std::string get(const std::string& k) const {
        const auto value = opt(k);
        if (value.empty())
            throw std::runtime_error("Missing --" + k);
        return value;
    }
    std::uint64_t num(const std::string& k, std::uint64_t fallback) const {
        const auto s = opt(k);
        return s.empty() ? fallback : number(s);
    }
    Shape shape() const {
        Shape s{num("n", 0), num("payload-length", 0), num("capacity", 2)};
        check(s.n >= 2 && s.n <= (1u << 20) && s.length >= 1 && s.length <= 8192 &&
                  s.capacity >= 1 && s.capacity <= 2048 && !(s.capacity & (s.capacity - 1)) &&
                  s.pbc_capacity() <= s.n,
              "Invalid N, payload length, or K");
        return s;
    }
    DatabaseId database() const { return {opt("db-id", default_db_id), num("db-version", 1)}; }
};

class Socket {
    int fd_ = -1;

  public:
    explicit Socket(int fd) : fd_(fd) { check(fd_ >= 0, "TCP socket creation or accept failed"); }
    Socket(Socket&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() {
        if (fd_ >= 0)
            close(fd_);
    }
    int get() const { return fd_; }
    void no_delay() const {
        const int on = 1;
        check(setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0,
              "TCP_NODELAY failed");
    }
};

sockaddr_in address(const std::string& host, std::uint64_t port) {
    check(port >= 1024 && port < 65536, "Invalid TCP port");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    check(inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1, "Expected an IPv4 address");
    return addr;
}

Socket listener(const std::string& host, std::uint64_t port) {
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    const int on = 1;
    const auto addr = address(host, port);
    check(setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0 &&
              bind(socket.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0 &&
              listen(socket.get(), 16) == 0,
          "TCP listen failed");
    return socket;
}

Socket connect_to(const std::string& host, std::uint64_t port) {
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    const auto addr = address(host, port);
    check(connect(socket.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0,
          "TCP connect failed");
    socket.no_delay();
    return socket;
}

Socket accept_from(const Socket& listener_socket) {
    int fd;
    do {
        fd = accept4(listener_socket.get(), nullptr, nullptr, SOCK_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    Socket socket(fd);
    socket.no_delay();
    return socket;
}

void send_all(const Socket& s, const void* ptr, std::size_t bytes) {
    auto p = static_cast<const char*>(ptr);
    while (bytes != 0) {
        const auto n = send(s.get(), p, bytes, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        check(n > 0, "TCP send failed");
        p += n;
        bytes -= n;
    }
}

void receive_all(const Socket& s, void* ptr, std::size_t bytes) {
    auto p = static_cast<char*>(ptr);
    while (bytes != 0) {
        const auto n = recv(s.get(), p, bytes, 0);
        if (n < 0 && errno == EINTR)
            continue;
        check(n > 0, "TCP receive failed or peer closed");
        p += n;
        bytes -= n;
    }
}

void send_message(const Socket& s, std::string_view body) {
    Bytes length;
    append64(length, body.size());
    send_all(s, length.data(), length.size());
    send_all(s, body.data(), body.size());
}

std::string receive_message(const Socket& s, std::size_t max_bytes, bool exact = false) {
    std::array<Byte, 8> header{};
    receive_all(s, header.data(), header.size());
    std::uint64_t n = 0;
    for (auto v : header)
        n = (n << 8) | v;
    check(n > 0 && n <= max_bytes && (!exact || n == max_bytes), "Unexpected TCP message length");
    std::string body(n, '\0');
    receive_all(s, body.data(), body.size());
    return body;
}

std::string db_header(const Args& args, const Shape& shape) {
    return "PBM-RETRIEVAL-1\n" + std::to_string(shape.n) + "\n" + std::to_string(shape.length) +
           "\n" + args.opt("db-id", default_db_id) + "\n" +
           std::to_string(args.num("db-version", 1)) + "\n";
}

Scalar load_server_key(const Args& args, const Shape& shape) {
    const fs::path dir = args.get("db-state");
    std::ifstream meta(dir / "metadata.txt", std::ios::binary);
    std::string actual((std::istreambuf_iterator<char>(meta)), {});
    check(actual == db_header(args, shape), "Database metadata mismatch");
    std::ifstream input(dir / "oprf.key", std::ios::binary);
    Scalar key{};
    read_exact(input, key.data(), key.size());
    check(input.peek() == EOF, "Unexpected OPRF key size");
    validate_scalar(key);
    return key;
}

void prepare_payload(const Args& args, const Shape& s) {
    const fs::path dir = args.get("db-state");
    const auto expected = s.n * s.record();
    if (fs::exists(dir)) {
        (void)load_server_key(args, s);
        check(fs::file_size(dir / "payload.enc") == expected, "Encrypted database size mismatch");
        std::cout << "{\"prepared\":true,\"reused\":true}\n";
        return;
    }
    const fs::path source = args.get("payload-file");
    check(fs::file_size(source) == s.n * s.length, "Raw Payload size mismatch");
    if (dir.has_parent_path())
        fs::create_directories(dir.parent_path());
    auto stage = dir;
    stage += ".building-" + std::to_string(getpid());
    check(fs::create_directory(stage), "Cannot create isolated Payload staging directory");
    const auto start = Clock::now();
    try {
        auto key = random_scalar();
        const auto db = args.database();
        std::ifstream in(source, std::ios::binary);
        std::ofstream out(stage / "payload.enc", std::ios::binary);
        Bytes raw(s.length);
        for (std::size_t row = 0; row < s.n; ++row) {
            read_exact(in, raw.data(), raw.size());
            auto record_key = derive_key(evaluate(key, db.input(row)), db, row);
            auto aad = db.aad(row);
            auto record = encrypt(raw, record_key, aad);
            check(decrypt(record, record_key, aad) == raw, "Payload build self-check failed");
            write_exact(out, record.data(), record.size());
            sodium_memzero(record_key.data(), record_key.size());
        }
        out.close();
        check(bool(out) && fs::file_size(stage / "payload.enc") == expected,
              "Encrypted database write failed");
        std::ofstream key_out(stage / "oprf.key", std::ios::binary);
        write_exact(key_out, key.data(), key.size());
        key_out.close();
        sodium_memzero(key.data(), key.size());
        std::ofstream metadata(stage / "metadata.txt", std::ios::binary);
        metadata << db_header(args, s);
        metadata.close();
        check(bool(key_out) && bool(metadata), "Database state write failed");
        fs::rename(stage, dir);
    } catch (...) {

        for (const auto* name : {"metadata.txt", "oprf.key", "payload.enc"})
            fs::remove(stage / name);
        fs::remove(stage);
        throw;
    }
    std::cout << "{\"prepared\":true,\"reused\":false,\"records_verified\":" << s.n
              << ",\"payload_prepare_ms\":" << elapsed(start) << "}\n";
}

Bytes load_bitmap_bytes(const fs::path& path, std::size_t n) {
    const auto length = (n + 7) / 8;
    check(fs::file_size(path) == length, "Invalid PBM bitmap length");
    Bytes data(length);
    std::ifstream in(path, std::ios::binary);
    read_exact(in, data.data(), length);
    return data;
}

std::vector<std::size_t> padded_rows(const Shape& s, const std::vector<std::size_t>& rows) {
    auto padded = rows;
    padded.reserve(s.pbc_capacity());
    std::unordered_set<std::size_t> seen(rows.begin(), rows.end());
    seen.reserve(s.pbc_capacity());
    while (padded.size() < s.pbc_capacity()) {
        const auto j = randombytes_uniform(s.n);
        if (seen.insert(j).second)
            padded.push_back(j);
    }
    return padded;
}

std::vector<Bytes> oprf_inputs(const Shape& s, const DatabaseId& db,
                               const std::vector<std::size_t>& rows) {
    std::vector<Bytes> inputs;
    inputs.reserve(s.capacity);
    for (auto j : rows)
        inputs.push_back(db.input(j));
    std::unordered_set<std::uint64_t> dummy;
    while (inputs.size() < s.capacity) {
        std::uint64_t id;
        randombytes_buf(&id, sizeof(id));
        if (dummy.insert(id).second)
            inputs.push_back(db.input(id, true));
    }
    return inputs;
}

Point read_point(std::string_view body, std::size_t i) {
    Point p{};
    std::memcpy(p.data(), body.data() + i * p.size(), p.size());
    return p;
}

struct ServerMetrics {
    double receive_ms{}, compute_ms{}, send_ms{}, wall_ms{};
    std::size_t upload{}, download{};
    PirServerTiming pir;
};

void serve(const Args& args, const Shape& shape) {
    auto key = load_server_key(args, shape);
    const auto startup = Clock::now();
    ServerPir pir;
    const fs::path pp = args.get("public-params");
    if (const auto saved = args.opt("aux"); !saved.empty())
        pir.load(shape, pp, saved);
    else
        pir.setup(shape, fs::path(args.get("db-state")) / "payload.enc", pp);
    const double setup_ms = elapsed(startup);
    const auto precompute = Clock::now();
    pir.prepare();
    const double precompute_ms = elapsed(precompute);
    const auto host = args.opt("bind", "127.0.0.1");
    auto p = listener(host, args.num("pir-port", 27101));
    auto o = listener(host, args.num("oprf-port", 27102));
    std::cout << "{\"ready\":true,\"pir_setup_ms\":" << setup_ms
              << ",\"pir_answer_preprocess_ms\":" << precompute_ms << "}" << std::endl;
    const auto queries = args.num("queries", 1);
    for (std::uint64_t seq = 0; seq < queries; ++seq) {
        auto pir_socket = accept_from(p);
        auto oprf_socket = accept_from(o);
        auto pir_worker = std::async(std::launch::async, [&pir, conn = std::move(pir_socket)] {
            ServerMetrics m;
            const auto begin = Clock::now();
            auto request = receive_message(conn, 1ULL << 30);
            m.receive_ms = elapsed(begin);
            m.upload = request.size();
            auto response = pir.answer(std::move(request), m.pir);
            m.download = response.size();
            const auto send = Clock::now();
            send_message(conn, response);
            m.send_ms = elapsed(send);
            m.wall_ms = elapsed(begin);
            return m;
        });
        auto oprf_worker =
            std::async(std::launch::async, [&key, &shape, conn = std::move(oprf_socket)] {
                ServerMetrics m;
                const auto begin = Clock::now();
                const auto request = receive_message(conn, shape.capacity * 32, true);
                m.receive_ms = elapsed(begin);
                const auto start = Clock::now();
                std::string response(request.size(), '\0');
                for (std::size_t i = 0; i < shape.capacity; ++i) {
                    const auto z = evaluate_point(key, read_point(request, i));
                    std::memcpy(response.data() + 32 * i, z.data(), 32);
                }
                m.compute_ms = elapsed(start);
                m.upload = request.size();
                m.download = response.size();
                const auto send = Clock::now();
                send_message(conn, response);
                m.send_ms = elapsed(send);
                m.wall_ms = elapsed(begin);
                return m;
            });
        try {
            const auto a = pir_worker.get(), b = oprf_worker.get();
            std::cout << "{\"seq\":" << seq << ",\"pir_server_answer_ms\":"
                      << a.pir.query_precompute_ms + a.pir.answer_compute_ms
                      << ",\"pir_server_request_receive_ms\":" << a.receive_ms
                      << ",\"pir_server_request_deserialize_ms\":" << a.pir.request_deserialize_ms
                      << ",\"pir_server_query_precompute_ms\":" << a.pir.query_precompute_ms
                      << ",\"pir_server_answer_compute_ms\":" << a.pir.answer_compute_ms
                      << ",\"pir_server_response_serialize_ms\":" << a.pir.response_serialize_ms
                      << ",\"pir_server_response_send_ms\":" << a.send_ms
                      << ",\"pir_server_branch_wall_ms\":" << a.wall_ms
                      << ",\"oprf_server_ms\":" << b.compute_ms
                      << ",\"oprf_server_request_receive_ms\":" << b.receive_ms
                      << ",\"oprf_server_evaluate_ms\":" << b.compute_ms
                      << ",\"oprf_server_response_send_ms\":" << b.send_ms
                      << ",\"oprf_server_branch_wall_ms\":" << b.wall_ms
                      << ",\"pir_upload_bytes\":" << a.upload
                      << ",\"pir_download_bytes\":" << a.download
                      << ",\"oprf_upload_bytes\":" << b.upload
                      << ",\"oprf_download_bytes\":" << b.download << "}" << std::endl;
        } catch (const std::exception& error) {
            std::cerr << "query " << seq << ": " << error.what() << std::endl;
            std::cout << "{\"seq\":" << seq << ",\"server_failed\":true}" << std::endl;
        }
    }
    sodium_memzero(key.data(), key.size());
}

void output_records(const fs::path& path, const std::vector<std::size_t>& rows,
                    const std::vector<Bytes>& records) {
    check(rows.size() == records.size(), "Invalid output record count");
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    Bytes header;
    append64(header, rows.size());
    write_exact(f, header.data(), header.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        header.clear();
        append64(header, rows[i]);
        write_exact(f, header.data(), header.size());
        write_exact(f, records[i].data(), records[i].size());
    }
    f.close();
    check(bool(f), "Cannot write query output");
}

struct PirRun {
    std::vector<std::size_t> padded;
    std::vector<Bytes> encrypted;
    std::size_t upload, download;
    double query_ms{}, wall_ms{}, upload_ms{}, receive_ms{};
    PirClientTiming timing;
    std::optional<pir::BatchResponseMessage> audit_response;
};

struct OprfRun {
    std::vector<Prf> real;
    std::size_t upload, download;
    double input_ms{}, blind_ms{}, upload_ms{}, receive_ms{}, finalize_ms{}, wall_ms{};
};

void query(const Args& args, const Shape& shape) {
    const auto data = load_bitmap_bytes(args.get("match-bitmap"), shape.n);
    const auto begin = Clock::now();
    const auto rows = decode_bitmap_rows(data, shape.n);
    const double index_extract_ms = elapsed(begin);
    check(rows.size() <= shape.capacity, "capacity_exceeded");
    const auto extract_mode = args.opt("extract-mode", "parallel");
    const auto crypto_mode = args.opt("crypto-mode", "reuse");
    const auto threads = args.num("client-extract-threads", 4);
    const auto audit_extract = args.num("audit-extract", 0);
    check((extract_mode == "serial" || extract_mode == "parallel") &&
              (crypto_mode == "oneshot" || crypto_mode == "reuse") && threads >= 1 &&
              threads <= 32 && audit_extract <= 1,
          "Invalid extract/crypto mode, thread count, or audit flag");
    const bool parallel = extract_mode == "parallel";
    const auto prep = Clock::now();
    const Public pp(shape, args.get("public-params"));
    ClientPir pir(pp, parallel || audit_extract ? threads : 0);
    std::vector<Blind> blinds(shape.capacity);
    for (auto& b : blinds)
        b = prepare_blind();
    std::unique_ptr<CryptoWorkerContext> crypto;
    if (crypto_mode == "reuse")
        crypto = std::make_unique<CryptoWorkerContext>();
    const double pre_ms = elapsed(prep);
    const auto db = args.database();
    const auto host = args.opt("host", "127.0.0.1");
    auto pir_socket = connect_to(host, args.num("pir-port", 27101));
    auto oprf_socket = connect_to(host, args.num("oprf-port", 27102));
    const auto start = Clock::now();
    auto pir_worker = std::async(std::launch::async, [&pir, &rows, &shape, parallel, audit_extract,
                                                      conn = std::move(pir_socket)] {
        const auto begin = Clock::now();
        PirRun result{};
        result.padded = padded_rows(shape, rows);
        auto request = pir.make_query(result.padded, result.timing);
        result.query_ms = elapsed(begin);
        result.upload = request.size();
        const auto upload = Clock::now();
        send_message(conn, request);
        result.upload_ms = elapsed(upload);
        const auto receive = Clock::now();
        auto response = receive_message(conn, 1ULL << 30);
        result.receive_ms = elapsed(receive);
        result.download = response.size();
        {
            const auto decode = Clock::now();
            auto decoded = pir.deserialize(std::move(response));
            result.timing.response_deserialize_ms = elapsed(decode);
            const auto extract = Clock::now();
            result.encrypted = pir.extract(decoded, parallel);
            result.timing.extract_ms = elapsed(extract);
            if (audit_extract)
                result.audit_response.emplace(std::move(decoded));
        }
        result.wall_ms = elapsed(begin);
        return result;
    });
    auto oprf_worker = std::async(
        std::launch::async, [&db, &rows, &shape, &blinds, conn = std::move(oprf_socket)] {
            const auto begin = Clock::now();
            const auto inputs = oprf_inputs(shape, db, rows);
            OprfRun result{};
            result.input_ms = elapsed(begin);
            const auto blind_start = Clock::now();
            std::string request(shape.capacity * 32, '\0');
            for (std::size_t i = 0; i < inputs.size(); ++i) {
                const auto b = blind(inputs[i], blinds[i].scalar);
                std::memcpy(request.data() + 32 * i, b.data(), 32);
            }
            result.blind_ms = elapsed(blind_start);
            const auto upload = Clock::now();
            send_message(conn, request);
            result.upload_ms = elapsed(upload);
            const auto receive = Clock::now();
            const auto response = receive_message(conn, request.size(), true);
            result.receive_ms = elapsed(receive);
            const auto finish = Clock::now();
            result.real.reserve(rows.size());
            for (std::size_t i = 0; i < inputs.size(); ++i) {
                auto w = finalize(inputs[i], blinds[i].inverse, read_point(response, i));
                if (i < rows.size())
                    result.real.push_back(w);
                sodium_memzero(w.data(), w.size());
            }
            result.finalize_ms = elapsed(finish);
            result.wall_ms = elapsed(begin);
            result.upload = request.size();
            result.download = response.size();
            return result;
        });
    auto a = pir_worker.get();
    auto b = oprf_worker.get();
    std::vector<Key> keys;
    keys.reserve(rows.size());
    const auto derive = Clock::now();
    for (std::size_t i = 0; i < rows.size(); ++i)
        keys.push_back(crypto ? crypto->derive_key(b.real[i], db, rows[i])
                              : derive_key(b.real[i], db, rows[i]));
    const double hkdf_ms = elapsed(derive);
    std::vector<Bytes> recovered;
    recovered.reserve(rows.size());
    const auto verify = Clock::now();
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto aad = db.aad(rows[i]);
        recovered.push_back(crypto ? crypto->decrypt(a.encrypted.at(i), keys[i], aad)
                                   : decrypt(a.encrypted.at(i), keys[i], aad));
    }
    const double aead_ms = elapsed(verify);
    const double total = elapsed(start);
    for (auto& k : keys)
        sodium_memzero(k.data(), k.size());
    sodium_memzero(blinds.data(), blinds.size() * sizeof(Blind));
    int noise_budget = -1;
    if (a.audit_response) {
        check(pir.extract(*a.audit_response, !parallel) == a.encrypted,
              "Serial and parallel extraction differ");
        noise_budget = pir.minimum_noise_budget(*a.audit_response);
    }
    output_records(args.get("output"), rows, recovered);
    if (const auto audit = args.opt("audit-cipher"); !audit.empty())
        output_records(audit, a.padded, a.encrypted);
    if (const auto audit = args.opt("audit-oprf"); !audit.empty()) {
        std::vector<Bytes> values;
        for (const auto& w : b.real)
            values.emplace_back(w.begin(), w.end());
        output_records(audit, rows, values);
    }
    for (auto& w : b.real)
        sodium_memzero(w.data(), w.size());
    const auto bytes = a.upload + a.download + b.upload + b.download;
    std::cout << "{\"N\":" << shape.n << ",\"payload_len\":" << shape.length
              << ",\"encrypted_record_len\":" << shape.record()
              << ",\"capacity_K\":" << shape.capacity
              << ",\"spirit_batch_size\":" << shape.pbc_capacity()
              << ",\"pbc_bucket_count\":" << shape.buckets() << ",\"t\":" << rows.size()
              << ",\"index_extract_ms\":" << index_extract_ms << ",\"client_prepare_ms\":" << pre_ms
              << ",\"pir_client_query_ms\":" << a.query_ms << ",\"pir_client_extract_ms\":"
              << a.timing.response_deserialize_ms + a.timing.extract_ms
              << ",\"pir_client_bind_ms\":" << a.timing.bind_ms
              << ",\"pir_query_serialize_ms\":" << a.timing.query_serialize_ms
              << ",\"pir_upload_ms\":" << a.upload_ms
              << ",\"pir_response_receive_ms\":" << a.receive_ms
              << ",\"pir_response_deserialize_ms\":" << a.timing.response_deserialize_ms
              << ",\"pir_client_decrypt_extract_ms\":" << a.timing.extract_ms
              << ",\"pir_client_branch_wall_ms\":" << a.wall_ms
              << ",\"oprf_client_ms\":" << b.input_ms + b.blind_ms + b.finalize_ms
              << ",\"oprf_input_prepare_ms\":" << b.input_ms
              << ",\"oprf_client_blind_ms\":" << b.blind_ms
              << ",\"oprf_client_upload_ms\":" << b.upload_ms
              << ",\"oprf_client_response_receive_ms\":" << b.receive_ms
              << ",\"oprf_client_finalize_ms\":" << b.finalize_ms
              << ",\"oprf_client_branch_wall_ms\":" << b.wall_ms << ",\"hkdf_ms\":" << hkdf_ms
              << ",\"aead_decrypt_ms\":" << aead_ms << ",\"total_parallel_wall_ms\":" << total
              << ",\"pir_upload_bytes\":" << a.upload << ",\"pir_download_bytes\":" << a.download
              << ",\"oprf_upload_bytes\":" << b.upload << ",\"oprf_download_bytes\":" << b.download
              << ",\"online_total_bytes\":" << bytes << ",\"recovered_count\":" << recovered.size();
    if (noise_budget >= 0)
        std::cout << ",\"extract_equivalent\":true,\"min_response_noise_budget_bits\":"
                  << noise_budget;
    std::cout << "}\n";
}

void evaluate_rows(const Args& args, const Shape& shape) {
    const auto rows =
        decode_bitmap_rows(load_bitmap_bytes(args.get("match-bitmap"), shape.n), shape.n);
    check(rows.size() <= shape.capacity, "capacity_exceeded");
    auto key = load_server_key(args, shape);
    const auto db = args.database();
    std::vector<Bytes> values;
    for (auto j : rows) {
        auto w = evaluate(key, db.input(j));
        values.emplace_back(w.begin(), w.end());
        sodium_memzero(w.data(), w.size());
    }
    output_records(args.get("output"), rows, values);
    sodium_memzero(key.data(), key.size());
}
}
}

int main(int argc, char** argv) {
    using namespace retrieval;
    try {
        umask(0077);
        check(sodium_init() >= 0, "libsodium initialization failed");
        const Args args(argc, argv);
        const auto shape = args.shape();
        if (args.action == "prepare-spirit" || (args.action == "serve" && args.opt("aux").empty()))
            check(shape.minimum_bytes() <= args.num("memory-budget-gib", 80) * (1ULL << 30),
                  "SPIRIT minimum memory exceeds benchmark budget");
        std::cout << std::setprecision(9);
        if (args.action == "prepare-payload")
            prepare_payload(args, shape);
        else if (args.action == "prepare-spirit") {
            const auto start = Clock::now();
            ServerPir p;
            const fs::path pub = args.get("public-params"), aux = args.get("aux");
            check(!fs::exists(pub) && !fs::exists(aux), "SPIRIT state already exists");
            p.setup(shape, args.get("encrypted-db"), pub);
            p.save(aux);
            std::cout << "{\"pir_setup_and_save_ms\":" << elapsed(start) << "}\n";
        } else if (args.action == "serve")
            serve(args, shape);
        else if (args.action == "query")
            query(args, shape);
        else if (args.action == "audit-oprf")
            evaluate_rows(args, shape);
        else if (args.action == "prepare") {
            const auto start = Clock::now();
            const Public pp(shape, args.get("public-params"));
            ClientPir pir(pp);
            std::vector<Blind> blinds(shape.capacity);
            for (auto& b : blinds)
                b = prepare_blind();
            sodium_memzero(blinds.data(), blinds.size() * sizeof(Blind));
            std::cout << "{\"client_prepare_ms\":" << elapsed(start) << "}\n";
        } else
            throw std::runtime_error("Unknown action");
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
