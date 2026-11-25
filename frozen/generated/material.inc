class Material {
    std::fstream file_;
    bool reading_;
    static void transfer(std::fstream& file, Byte* data, std::size_t length, bool reading) {
        if (!length)
            return;
        if (reading)
            file.read(reinterpret_cast<char*>(data), length);
        else
            file.write(reinterpret_cast<const char*>(data), length);
        require(bool(file), "Cannot transfer material");
    }

  public:
    Material(const Config& c, bool server, unsigned slot, const std::string& name, bool reading)
        : file_(c.path(server, slot, name),
                std::ios::binary | (reading ? std::ios::in : (std::ios::out | std::ios::trunc))),
          reading_(reading) {
        require(bool(file_), "Cannot open party material");
        auto header = c.signature();
        put_word(header, server, 1);
        put_word(header, slot, 4);
        if (reading)
            require(read(header.size()) == header, "Material configuration/version mismatch");
        else
            write(header);
    }
    void write(const Bytes& data) {
        require(!reading_, "Material is read only");
        transfer(file_, const_cast<Byte*>(data.data()), data.size(), false);
    }
    Bytes read(std::size_t size) {
        require(reading_, "Material is write only");
        Bytes data(size);
        transfer(file_, data.data(), size, true);
        return data;
    }
    void finish() {
        if (reading_)
            require(file_.peek() == std::char_traits<char>::eof(), "Unexpected material bytes");
        file_.close();
        if (!reading_)
            require(bool(file_), "Material flush failed");
    }
};

void write_u16(Material& file, const std::vector<std::uint16_t>& input) {
    Bytes temp;
    temp.reserve(65536);
    for (const auto v : input) {
        put_word(temp, v, 2);
        if (temp.size() == 65536) {
            file.write(temp);
            temp.clear();
        }
    }
    file.write(temp);
}
std::vector<std::uint16_t> read_u16(Material& file, std::size_t n) {
    std::vector<std::uint16_t> out(n);
    for (std::size_t offset = 0; offset < n;) {
        const auto take = std::min<std::size_t>(n - offset, 32768);
        const auto data = file.read(take * 2);
        for (std::size_t j = 0; j < take; ++j)
            out[offset + j] = word(data.data() + 2 * j, 2);
        offset += take;
    }
    return out;
}
void write_eq(Material& file, const EqState& state) {
    file.write(state.r);
    file.write(state.lookup);
    write_u16(file, state.a);
    write_u16(file, state.mask);
}
EqState read_eq(Material& file, const EqLayout& shape) {
    return {file.read(bytes(shape.bits)), file.read(bytes(shape.tables)),
            read_u16(file, shape.bits), read_u16(file, shape.items)};
}
