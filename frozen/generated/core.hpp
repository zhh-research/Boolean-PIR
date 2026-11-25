#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <span>
#include <cstring>
#include <thread>
#include <vector>

namespace pbm {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Word = std::uint64_t;
using Clock = std::chrono::steady_clock;

inline void require(bool ok, const char* message) {
    if (!ok)
        throw std::runtime_error(message);
}

inline double ms(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

inline std::size_t bytes(std::size_t n) { return (n + 7) / 8; }
inline bool bit(const Bytes& v, std::size_t i) { return (v[i / 8] >> (i % 8)) & 1; }
inline void toggle(Bytes& v, std::size_t i) { v[i / 8] ^= Byte(1u << (i % 8)); }
inline void clear_tail(Bytes& v, std::size_t n) {
    if (n % 8)
        v.back() &= Byte((1u << (n % 8)) - 1);
}
inline void xor_into(Bytes& dest, const Bytes& src) {
    require(dest.size() == src.size(), "XOR length mismatch");
    for (std::size_t i = 0; i < dest.size(); ++i)
        dest[i] ^= src[i];
}
inline void random_bytes(Byte* dst, std::size_t size) {
    while (size) {
        const auto count = getrandom(dst, std::min<std::size_t>(size, 1 << 20), 0);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "OS entropy unavailable");
        size -= count;
        dst += count;
    }
}
inline Bytes random_bits(std::size_t n) {
    Bytes v(bytes(n));
    random_bytes(v.data(), v.size());
    clear_tail(v, n);
    return v;
}

inline void put_word(Bytes& out, Word value, unsigned size = 8) {
    for (unsigned i = 0; i < size; ++i)
        out.push_back(Byte(value >> (8 * i)));
}
inline Word word(const Byte* data, unsigned size = 8) {
    Word value = 0;
    for (unsigned i = 0; i < size; ++i)
        value |= Word(data[i]) << (8 * i);
    return value;
}
inline Word number(const std::string& value) {
    Word result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size(),
            "Invalid number");
    return result;
}
inline std::vector<std::string> split(const std::string& input) {
    std::vector<std::string> items;
    std::size_t start = 0;
    for (std::size_t end = 0; end <= input.size(); ++end) {
        if (end != input.size() && input[end] != ',')
            continue;
        require(end != start, "Empty configuration token");
        items.push_back(input.substr(start, end - start));
        start = end + 1;
    }
    return items;
}
inline Bytes read_file(const std::string& path, std::size_t expected) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    require(in && in.tellg() == std::streamoff(expected), "Invalid input file size");
    Bytes buffer(expected);
    in.seekg(0);
    if (expected)
        in.read(reinterpret_cast<char*>(buffer.data()), expected);
    require(bool(in), "Input read failed");
    return buffer;
}
inline std::vector<Word> read_words(const std::string& path, std::size_t n) {
    std::vector<Word> result(n);
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    require(in && in.tellg() == std::streamoff(n * 8), "Invalid input word file size");
    in.seekg(0);
    std::array<Byte, 65536> buffer;
    for (std::size_t i = 0; i < n;) {
        const auto take = std::min(n - i, buffer.size() / 8);
        in.read(reinterpret_cast<char*>(buffer.data()), take * 8);
        require(bool(in), "Input read failed");
        for (std::size_t j = 0; j < take; ++j)
            result[i + j] = word(buffer.data() + 8 * j);
        i += take;
    }
    return result;
}
inline void write_file(const std::string& path, const Bytes& value) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    require(bool(out), "Cannot open output");
    if (!value.empty())
        out.write(reinterpret_cast<const char*>(value.data()), value.size());
    out.close();
    require(bool(out), "Output write failed");
}

class Tcp {
    int fd_ = -1;
    Word query_, slot_;
    static constexpr Word magic = 0x314d4250;
    static constexpr std::size_t header_size = 40;

    void io(Byte* data, std::size_t size, bool sending) {
        while (size) {
            const auto count =
                sending ? ::send(fd_, data, size, MSG_NOSIGNAL) : ::recv(fd_, data, size, 0);
            if (count < 0 && errno == EINTR)
                continue;
            require(count > 0, sending ? "Socket send failed" : "Socket receive failed");
            size -= count;
            data += count;
            (sending ? sent : received) += count;
        }
    }

  public:
    Word sent = 0, received = 0, sent_frames = 0, received_frames = 0;
    Tcp(bool server, unsigned port, Word query, Word slot) : query_(query), slot_(slot) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (server) {
            const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            require(listener >= 0, "Socket creation failed");
            const int enabled = 1;
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
            if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
                listen(listener, 1)) {
                close(listener);
                throw std::runtime_error("Cannot listen on loopback port");
            }
            fd_ = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            close(listener);
        } else {
            for (int attempt = 0; attempt < 200 && fd_ < 0; ++attempt) {
                int peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
                require(peer >= 0, "Socket creation failed");
                if (connect(peer, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
                    fd_ = peer;
                else {
                    close(peer);
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                }
            }
        }
        require(fd_ >= 0, "Unable to connect parties");
        const int enabled = 1;
        setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    }
    ~Tcp() {
        if (fd_ >= 0)
            close(fd_);
    }
    Tcp(const Tcp&) = delete;
    Tcp& operator=(const Tcp&) = delete;

    void send(unsigned type, unsigned index, std::span<const Byte> body, unsigned batch = 0) {
        Bytes h;
        put_word(h, magic, 4);
        put_word(h, type, 4);
        put_word(h, index, 4);
        put_word(h, batch, 4);
        put_word(h, query_);
        put_word(h, slot_);
        put_word(h, body.size());
        io(h.data(), h.size(), true);
        io(const_cast<Byte*>(body.data()), body.size(), true);
        ++sent_frames;
    }
    Bytes receive(unsigned type, unsigned index, std::size_t limit, bool exact = true,
                  unsigned batch = 0) {
        std::array<Byte, header_size> h;
        io(h.data(), h.size(), false);
        const Word length = word(h.data() + 32);
        require(word(h.data(), 4) == magic && word(h.data() + 4, 4) == type &&
                    word(h.data() + 8, 4) == index && word(h.data() + 12, 4) == batch &&
                    word(h.data() + 16) == query_ && word(h.data() + 24) == slot_ &&
                    length <= limit && (!exact || length == limit),
                "Invalid frame");
        Bytes body(length);
        io(body.data(), body.size(), false);
        ++received_frames;
        return body;
    }
    void receive_into(unsigned type, unsigned index, std::span<Byte> body) {
        std::array<Byte, header_size> h;
        io(h.data(), h.size(), false);
        require(word(h.data(), 4) == magic && word(h.data() + 4, 4) == type &&
                    word(h.data() + 8, 4) == index && word(h.data() + 12, 4) == 0 &&
                    word(h.data() + 16) == query_ && word(h.data() + 24) == slot_ &&
                    word(h.data() + 32) == body.size(),
                "Invalid bulk frame");
        io(body.data(), body.size(), false);
        ++received_frames;
    }
    Word framing() const { return header_size * (sent_frames + received_frames); }
};

struct Gate {
    unsigned left, right;
    char op;
    unsigned level;
};
struct Formula {
    std::vector<Gate> gates;
    unsigned output = 0, depth = 0;
    Formula(unsigned k, const std::string& text) {
        std::vector<unsigned> stack;
        std::vector<unsigned> levels(k, 0);
        for (const auto& token : split(text)) {
            if (token == "!" || token == "&" || token == "|") {
                require(stack.size() >= (token == "!" ? 1 : 2), "Invalid postfix formula");
                const unsigned right = stack.back();
                stack.pop_back();
                const unsigned left = token == "!" ? right : stack.back();
                if (token != "!")
                    stack.pop_back();
                const unsigned level = std::max(levels[left], levels[right]) + 1;
                gates.push_back({left, right, token[0], level});
                stack.push_back(levels.size());
                levels.push_back(level);
                depth = std::max(depth, level);
            } else {
                const auto i = number(token);
                require(i < k, "Predicate index out of range");
                stack.push_back(i);
            }
        }
        require(stack.size() == 1, "Invalid postfix formula");
        output = stack.back();
    }
    unsigned products() const {
        return std::count_if(gates.begin(), gates.end(), [](auto g) { return g.op != '!'; });
    }
};

}
