# Boolean-PIR

## Build

On Ubuntu x86-64 with AVX2 and AES-NI, use GCC 11+, CMake 3.20+, and Python 3.10+.

```bash
sudo apt install build-essential cmake ninja-build git python3 pkg-config \
    libssl-dev libsodium-dev nasm autoconf automake libtool curl wget
bash scripts/build.sh
```

## Run

- Place `database.u64` and `query.u64` in the input directory. Store the `N` database rows in column-major order and one query value per column. Encode each 32-bit value as little-endian uint64.
- `DOMAINS` lists distinct value counts by column, separated by commas. `FORMULA` is comma-separated postfix with zero-based column indices and `&`, `|`, `!`.
- `payload.bin` stores `N` records of `L` bytes in row order. Public capacity `K` is a power of two between the match count and `min(N, 2048)`.

```bash
python3 scripts/run.py --input /path/to/input --n "$N" \
    --domains "$DOMAINS" --formula "$FORMULA" \
    --payload /path/to/payload.bin --payload-length "$L" --capacity "$K" \
    --output results/run
```

Use a new directory for `--output`.
