#include "eq.hpp"
#include "beaver.hpp"
#include <filesystem>
#include <iostream>
#include <memory>
#include <sodium/crypto_hash_sha256.h>
#include <sys/stat.h>

namespace pbm {
namespace fs = std::filesystem;

struct Config {
    std::map<std::string, std::string> flags;
    std::string action, data, materials, db_id, pool, mode, formula, kernel, layout, map_mode;
    std::vector<unsigned> domains;
    unsigned n, k, slots, slot, port;
    Word query_id;
    bool row, packed, fused, fast_input, map_probe;

    std::string get(const std::string& key, const std::string& fallback = {}) const {
        const auto it = flags.find(key);
        return it == flags.end() ? fallback : it->second;
    }
    unsigned num(const std::string& key, unsigned fallback, unsigned bound) const {
        const auto x = number(get(key, std::to_string(fallback)));
        require(x <= bound, "Invalid numeric option");
        return x;
    }
    explicit Config(int argc, char** argv) {
        require(argc >= 2 && argc % 2 == 0, "Usage: pbm_frozen ACTION --key value ...");
        action = argv[1];
        for (int i = 2; i < argc; i += 2) {
            const std::string key = argv[i];
            require(key.starts_with("--") && flags.emplace(key.substr(2), argv[i + 1]).second,
                    "Invalid option");
        }
        n = num("n", 0, 1u << 20);
        for (const auto& value : split(get("domains"))) {
            const auto d = number(value);
            require(d && d <= n, "Invalid domain size");
            domains.push_back(d);
        }
        k = domains.size();
        slots = num("slots", 1, 128);
        slot = num("slot", 0, 127);
        port = num("port", 21200, 65534);
        require(k && k <= 10 && slots && slot < slots && port > 1024, "Invalid dimensions");
        const auto scheme = get("scheme", "domain");
        require(scheme == "domain" || scheme == "row",
                "Only the frozen domain protocol and row references exist");
        row = scheme == "row";
        packed = num("packed", 1, 1);
        fused = num("fused", !row, 1);
        fast_input = num("fast-input", 1, 1);
        map_probe = num("map-probe", 0, 1);
        require(!row || (!fused && !map_probe), "Row reference does not expand");
        kernel = get("kernel", "avx2");
        layout = get("layout", "layer");
        require(layout == "layer" || layout == "column" || layout == "record",
                "Invalid Beaver layout");
        map_mode = get("map", "lookup");
        require(map_mode == "lookup" || map_mode == "list" || map_mode == "scan",
                "Invalid server map kernel");
        mode = get("mode", "fresh");
        require(mode == "fresh" || mode == "replay", "Invalid reuse mode");
        data = get("data");
        materials = get("materials");
        db_id = get("database-id");
        pool = get("pool-id");
        require(db_id.size() == 64 && pool.size() == 32 &&
                    (db_id + pool).find_first_not_of("0123456789abcdef") == std::string::npos,
                "Expected public database and material pool identities");
        require(!materials.empty() && (action == "dealer" || !data.empty()), "Missing paths");
        formula = get("formula");
        query_id = number(get("query-id", "1"));
    }
    std::string path(bool server, unsigned s, const std::string& ext) const {
        return materials + "/" + (server ? "server/" : "client/") + std::to_string(s) + "." + ext;
    }
    Bytes signature() const {
        const auto str = "PBM3\n" + std::to_string(n) + "\n" + get("domains") + "\n" +
                         std::to_string(slots) + "\n" + (row ? "row" : "domain") + "\n" + mode +
                         "\n" + formula + "\n" + db_id + "\n" + pool + "\n";
        return Bytes(str.begin(), str.end());
    }
};

#include "material.inc"

struct Shape {
    EqLayout eq;
    Formula formula;
    BooleanPlan boolean;
    explicit Shape(const Config& c) : formula(c.k, c.formula), boolean(formula, c.k) {
        for (const auto d : c.domains)
            eq.add(c.row ? c.n : d, 32);
    }
};

Word peak_kib() {
    std::ifstream input("/proc/self/status");
    for (std::string line; std::getline(input, line);)
        if (line.starts_with("VmHWM:"))
            return std::stoull(line.substr(6));
    throw std::runtime_error("VmHWM missing");
}
double cpu_ms() {
    rusage v{};
    getrusage(RUSAGE_SELF, &v);
    return 1000.0 * (v.ru_utime.tv_sec + v.ru_stime.tv_sec) +
           .001 * (v.ru_utime.tv_usec + v.ru_stime.tv_usec);
}
struct Stage {
    Clock::time_point tick;
    Word sent, received;
    explicit Stage(const Tcp& tcp) : tick(Clock::now()), sent(tcp.sent), received(tcp.received) {}
};

void dealer(const Config& c, const Shape& s) {
    const auto start = Clock::now();
    require(!fs::exists(c.materials), "Material pool already exists");
    fs::create_directories(c.materials + "/client");
    fs::create_directories(c.materials + "/server");
    double triples_ms = 0, eq_ms = 0;
    for (unsigned slot = 0; slot < c.slots; ++slot) {
        auto t = Clock::now();
        {
            auto triples = TripleDealer::generate(s.boolean, c.n);
            Material client(c, false, slot, "triple", false),
                server(c, true, slot, "triple", false);
            client.write(triples[0]);
            server.write(triples[1]);
            client.finish();
            server.finish();
        }
        triples_ms += ms(t);
        t = Clock::now();
        {
            auto eq = dealer_eq(s.eq);
            Material client(c, false, slot, "eq", false), server(c, true, slot, "eq", false);
            write_eq(client, eq[0]);
            write_eq(server, eq[1]);
            client.finish();
            server.finish();
        }
        eq_ms += ms(t);
    }
    std::cout << "{\"offline_dealer_ms\":" << ms(start) << ",\"offline_triples_ms\":" << triples_ms
              << ",\"offline_eq_ms\":" << eq_ms << ",\"peak_rss_kib\":" << peak_kib() << "}\n";
}

struct Data {
    std::vector<Word> rows;
    std::vector<Domain> domains;
    Data(const Config& c, bool server) {
        if (!server)
            return;
        const auto path = c.data + "/database.u64";
        std::ifstream input(path, std::ios::binary);
        require(bool(input), "Database file unavailable");
        Bytes buffer(1 << 20);
        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);
        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            crypto_hash_sha256_update(&state, buffer.data(), input.gcount());
        }
        require(input.eof() && !input.bad(), "Database fingerprint read failed");
        std::array<unsigned char, 32> hash;
        crypto_hash_sha256_final(&state, hash.data());
        constexpr char hex[] = "0123456789abcdef";
        std::string encoded;
        for (auto byte : hash) {
            encoded += hex[byte >> 4];
            encoded += hex[byte & 15];
        }
        require(encoded == c.db_id, "Database fingerprint changed; regenerate the pool");
        rows = read_words(path, std::size_t(c.n) * c.k);
        if (!c.row) {
            for (unsigned i = 0; i < c.k; ++i)
                domains.push_back(domain(rows, i, c.n, 32, c.domains[i]));
            rows.clear();
            rows.shrink_to_fit();
        }
    }
};

void expand_pool(const Config& c, bool server) {
    require(!c.row, "Rows need no expansion materials");
    for (unsigned i = 0; i < c.slots; ++i)
        require(!fs::exists(c.path(server, i, "expand")) && !fs::exists(c.path(server, i, "used")),
                "Expansion slot already exists or is consumed");
    const Data db(c, server);
    Tcp tcp(server, c.port, c.query_id, 0);
    Ot ot(server, c.port + 1);
    const auto start = Clock::now();
    if (std::any_of(c.domains.begin(), c.domains.end(), [](auto d) { return d > 1; }))
        ot.initialize(server);
    const double base_ms = ms(start);
    std::vector<std::vector<Masks>> result;
    std::vector<RotStats> stats(c.k);
    const std::vector<std::uint32_t> none;
    for (unsigned i = 0; i < c.k; ++i)
        result.push_back(rot_expand(tcp, ot, server, i, c.n, c.domains[i], c.slots,
                                    server ? db.domains[i].map : none, stats[i]));
    for (unsigned s = 0; s < c.slots; ++s) {
        Material file(c, server, s, "expand", false);
        for (const auto& col : result) {
            if (!server)
                file.write(col[s].r);
            file.write(col[s].row);
        }
        file.finish();
    }
    std::cout << "{\"offline_expand_ms\":" << ms(start) << ",\"base_ot_ms\":" << base_ms
              << ",\"sent\":" << tcp.sent + ot.sent()
              << ",\"received\":" << tcp.received + ot.received()
              << ",\"peak_rss_kib\":" << peak_kib() << ",\"columns\":[";
    for (unsigned i = 0; i < c.k; ++i) {
        const auto& a = stats[i];
        if (i)
            std::cout << ",";
        std::cout << "{\"D\":" << c.domains[i]
                  << ",\"rot_count\":" << Word(c.domains[i] - 1) * c.slots << ",\"rot_ms\":" << a.ot
                  << ",\"prg_ms\":" << a.prg << ",\"gamma_ms\":" << a.gamma
                  << ",\"eta_ms\":" << a.eta << ",\"group_ms\":" << a.mapping
                  << ",\"total_ms\":" << a.total << ",\"sent\":" << a.sent
                  << ",\"received\":" << a.received << "}";
    }
    std::cout << "]}\n";
}

Bytes encode(const Config& c, const Shape& s, const Data& db, bool server) {
    Bytes bits(bytes(s.eq.bits));
    const auto query = server ? std::vector<Word>{} : read_words(c.data + "/query.u64", c.k);
    for (unsigned i = 0; i < c.k; ++i) {
        const auto g = s.eq.groups[i];
        for (std::size_t j = 0; j < g.count; ++j) {
            const auto x =
                server ? (c.row ? db.rows[i * c.n + j] : db.domains[i].values[j]) : query[i];
            require(x <= UINT32_MAX, "Invalid 32-bit input");
            const auto at = g.bit_start + j * 32;
            if (c.fast_input) {
                auto* p = bits.data() + at / 8;
                p[0] = Byte(x);
                p[1] = Byte(x >> 8);
                p[2] = Byte(x >> 16);
                p[3] = Byte(x >> 24);
            } else {
                for (unsigned b = 0; b < 32; ++b)
                    if ((x >> b) & 1)
                        toggle(bits, at + b);
            }
        }
    }
    return bits;
}

struct MapPlan {
    std::vector<std::uint16_t> compact;
    std::vector<std::vector<std::uint32_t>> positions;
    MapPlan(const Domain& d, bool lookup, bool list) {
        if (lookup && d.values.size() <= 65536)
            compact.assign(d.map.begin(), d.map.end());
        if (list) {
            positions.resize(d.values.size());
            for (unsigned j = 0; j < d.map.size(); ++j)
                positions[d.map[j]].push_back(j);
        }
    }
};
inline void apply_map(Bytes& row, const Bytes& adjusted, const Domain& domain, const MapPlan& plan,
                      const std::string& how) {
    if (how == "list") {
        for (unsigned d = 0; d < plan.positions.size(); ++d)
            if (bit(adjusted, d))
                for (const auto j : plan.positions[d])
                    toggle(row, j);
    } else if (how == "lookup") {
        Bytes unpacked(domain.values.size());
        for (unsigned d = 0; d < unpacked.size(); ++d)
            unpacked[d] = bit(adjusted, d);
        const auto update = [&](const auto& index) {
            std::size_t j = 0;
            for (; j + 8 <= index.size(); j += 8) {
                const unsigned bits =
                    unpacked[index[j]] | (unpacked[index[j + 1]] << 1) |
                    (unpacked[index[j + 2]] << 2) | (unpacked[index[j + 3]] << 3) |
                    (unpacked[index[j + 4]] << 4) | (unpacked[index[j + 5]] << 5) |
                    (unpacked[index[j + 6]] << 6) | (unpacked[index[j + 7]] << 7);
                row[j / 8] ^= Byte(bits);
            }
            for (; j < index.size(); ++j)
                if (unpacked[index[j]])
                    toggle(row, j);
        };
        if (plan.compact.empty())
            update(domain.map);
        else
            update(plan.compact);
    } else {
        for (unsigned j = 0; j < domain.map.size(); ++j)
            if (bit(adjusted, domain.map[j]))
                toggle(row, j);
    }
}

void consume(const Config& c, bool server) {
    if (c.mode == "replay")
        return;
    const auto path = c.path(server, c.slot, "used");
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    require(fd >= 0, "Fresh slot already used or inaccessible");
    const auto ok = fsync(fd);
    close(fd);
    require(ok == 0, "Cannot persist used marker");
    const int dir = open(fs::path(path).parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(dir >= 0, "Cannot open material directory");
    const auto saved = fsync(dir);
    close(dir);
    require(saved == 0, "Cannot persist material directory");
}

void party(const Config& c, const Shape& s, bool server) {
    const auto setup = Clock::now();
    const Data db(c, server);
    std::vector<MapPlan> maps;
    if (server && !c.row)
        for (const auto& d : db.domains)
            maps.emplace_back(d, c.map_mode == "lookup" || c.map_probe,
                              c.map_mode == "list" || c.map_probe);
    Material ef(c, server, c.slot, "eq", true), tf(c, server, c.slot, "triple", true);
    auto state = read_eq(ef, s.eq);
    ef.finish();
    const auto w = bytes(c.n);
    auto triples = tf.read(3 * w * s.boolean.products);
    tf.finish();
    const bool legacy = c.kernel == "legacy";
    auto old =
        legacy ? legacy_triples(s.boolean, s.formula, c.k, triples, w) : std::vector<Triple>{};
    auto kernel = legacy ? nullptr : choose_kernel(c.kernel);
    std::unique_ptr<BooleanWorkspace> workspace;
    if (legacy)
        Bytes().swap(triples);
    else
        workspace =
            std::make_unique<BooleanWorkspace>(s.boolean, s.formula, c.k, w, c.layout == "record");
    std::vector<Masks> masks;
    std::vector<Bytes> diagnostic_masks;
    std::size_t correction_bytes = 0;
    if (!c.row) {
        Material ex(c, server, c.slot, "expand", true);
        for (const auto d : c.domains) {
            const auto dw = bytes(d);
            masks.push_back({server ? Bytes{} : ex.read(dw), ex.read(w)});
            if (server && c.map_probe)
                diagnostic_masks.push_back(masks.back().row);
            correction_bytes += dw;
        }
        ex.finish();
    }
    Bytes input;
    if (server)
        input = encode(c, s, db, true);
    consume(c, server);
    Tcp tcp(server, c.port, c.query_id, c.slot);
    auto signature = c.signature();
    for (const auto& v :
         {c.kernel, c.layout, c.map_mode, std::to_string(c.packed), std::to_string(c.fused)}) {
        put_word(signature, v.size(), 4);
        signature.insert(signature.end(), v.begin(), v.end());
    }
    if (!server)
        tcp.send(1, 0, signature);
    require(tcp.receive(1, 0, signature.size()) == signature, "Party configuration mismatch");
    if (server)
        tcp.send(1, 0, signature);
    const double setup_ms = ms(setup);
    const Word frames0 = tcp.sent_frames + tcp.received_frames;
    const Stage whole(tcp);
    const double cpu0 = cpu_ms();
    if (!server)
        input = encode(c, s, db, false);
    const double input_ms = ms(whole.tick);
    Bytes received;
    const auto attach = [&](const std::vector<Bytes>& a) {
        Bytes tail;
        tail.reserve(correction_bytes);
        for (unsigned i = 0; i < c.k; ++i)
            for (unsigned j = 0; j < a[i].size(); ++j)
                tail.push_back(a[i][j] ^ masks[i].r[j]);
        return tail;
    };
    const Stage eq(tcp);
    auto shares = online_eq(tcp, server, s.eq, state, std::move(input), c.packed, nullptr, attach,
                            c.fused ? correction_bytes : 0, &received);
    const double eq_ms = ms(eq.tick);
    const Word eq_sent = tcp.sent - eq.sent, eq_received = tcp.received - eq.received;
    const Stage expand(tcp);
    double map_ms = 0;
    std::vector<Bytes> diagnostic_adjusted;
    std::size_t offset = 0;
    if (!c.row)
        for (unsigned i = 0; i < c.k; ++i) {
            auto& eq_share = shares[i];
            if (server) {
                if (!c.fused)
                    xor_into(eq_share, tcp.receive(10, i, bytes(c.domains[i])));
                else {
                    for (unsigned j = 0; j < eq_share.size(); ++j)
                        eq_share[j] ^= received[offset + j];
                    offset += eq_share.size();
                }
                const auto t = Clock::now();
                apply_map(masks[i].row, eq_share, db.domains[i], maps[i], c.map_mode);
                map_ms += ms(t);
                if (c.map_probe)
                    diagnostic_adjusted.push_back(std::move(eq_share));
            } else if (!c.fused) {
                xor_into(eq_share, masks[i].r);
                tcp.send(10, i, eq_share);
            }
            eq_share = std::move(masks[i].row);
        }
    const double expand_ms = ms(expand.tick);
    const Word expand_sent = tcp.sent - expand.sent,
               expand_received = tcp.received - expand.received;
    const Stage boolean(tcp);
    unsigned bool_rounds = 0;
    double bool_cpu = 0;
    auto output =
        legacy ? boolean_tree(tcp, server, s.formula, std::move(shares), old, c.n, bool_rounds)
               : boolean_packed(tcp, server, s.formula, s.boolean, std::move(shares), triples, c.n,
                                kernel, c.layout, *workspace, bool_rounds, bool_cpu);
    const double bool_ms = ms(boolean.tick);
    const Word bool_sent = tcp.sent - boolean.sent, bool_received = tcp.received - boolean.received;
    const Stage reconstruct(tcp);
    if (server)
        tcp.send(50, 0, output);
    else
        xor_into(output, tcp.receive(50, 0, w));
    const double total = ms(whole.tick), reconstruct_ms = ms(reconstruct.tick),
                 online_cpu = cpu_ms() - cpu0;
    const auto peak = peak_kib();
    std::array<double, 3> probes{};
    if (server && c.map_probe)
        for (unsigned i = 0; i < c.k; ++i) {
            std::array<Bytes, 3> trial{diagnostic_masks[i], diagnostic_masks[i],
                                       diagnostic_masks[i]};
            constexpr std::array<const char*, 3> methods{"scan", "lookup", "list"};
            for (unsigned j = 0; j < methods.size(); ++j) {
                const auto method = (j + c.slot) % methods.size();
                const auto t = Clock::now();
                apply_map(trial[method], diagnostic_adjusted[i], db.domains[i], maps[i],
                          methods[method]);
                probes[method] += ms(t);
            }
            require(trial[0] == trial[1] && trial[0] == trial[2],
                    "Map kernels differ on actual correction shares");
        }
    if (!server) {
        require(!c.get("out").empty(), "Missing client bitmap path");
        write_file(c.get("out"), output);
    }
    std::cout << "{\"online_total_ms\":" << total << ",\"online_cpu_ms\":" << online_cpu
              << ",\"setup_ms\":" << setup_ms << ",\"input_ms\":" << input_ms
              << ",\"eq_ms\":" << eq_ms << ",\"expand_ms\":" << expand_ms
              << ",\"map_ms\":" << map_ms << ",\"boolean_ms\":" << bool_ms
              << ",\"boolean_local_ms\":" << bool_cpu << ",\"reconstruct_ms\":" << reconstruct_ms
              << ",\"sent\":" << tcp.sent - whole.sent
              << ",\"received\":" << tcp.received - whole.received << ",\"eq_sent\":" << eq_sent
              << ",\"eq_received\":" << eq_received << ",\"expand_sent\":" << expand_sent
              << ",\"expand_received\":" << expand_received << ",\"boolean_sent\":" << bool_sent
              << ",\"boolean_received\":" << bool_received
              << ",\"messages\":" << tcp.sent_frames + tcp.received_frames - frames0
              << ",\"rounds\":" << 3 + bool_rounds + (!c.row && !c.fused)
              << ",\"round_trips\":" << 2 + bool_rounds << ",\"boolean_rounds\":" << bool_rounds
              << ",\"eq_count\":" << s.eq.items
              << ",\"and_gates\":" << Word(s.boolean.products) * c.n << ",\"peak_rss_kib\":" << peak
              << ",\"probe_scan_ms\":" << probes[0] << ",\"probe_lookup_ms\":" << probes[1]
              << ",\"probe_list_ms\":" << probes[2] << "}\n";
}
}

int main(int argc, char** argv) {
    umask(0077);
    try {
        const pbm::Config c(argc, argv);
        const pbm::Shape shape(c);
        if (c.action == "dealer")
            pbm::dealer(c, shape);
        else if (c.action == "ot-server" || c.action == "ot-client")
            pbm::expand_pool(c, c.action == "ot-server");
        else if (c.action == "server" || c.action == "client")
            pbm::party(c, shape, c.action == "server");
        else
            throw std::runtime_error("Unknown frozen protocol action");
    } catch (const std::exception& e) {
        std::cerr << "pbm_frozen: " << e.what() << '\n';
        return 1;
    }
}
