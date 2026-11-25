# Boolean-PIR

## Dependencies

- Linux x86-64 with AVX2 and AES-NI, GCC/G++ 11 or newer, CMake 3.20 or newer, Ninja, Git, and Python 3.10 or newer.
- OpenSSL and libsodium development headers, pkg-config, OpenMP, NASM, and the GNU build tools.

On Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build git python3 pkg-config \
    libssl-dev libsodium-dev nasm autoconf automake libtool curl wget
```

## Build

```bash
bash scripts/build.sh
```

The script builds against the pinned libOTe and SPIRIT revisions in `.deps/`. To use already built dependencies, set `LIBOTE_SOURCE`, `SPIRIT_SOURCE`, and `SPIRIT_BUILD`. Set `LIBOTE_BUILD` and `LIBOTE_PREFIX` when libOTe uses a custom build or install directory.

## Run

Prepare an input directory containing `database.u64` and `query.u64`. Store the database column by column, with `N` little-endian uint64 values in each column. The query contains one such value per column. Attribute and query values must fit in 32 bits. Pass the number of distinct database values in each column as a comma-separated list in `--domains`.

Pass a comma-separated postfix expression in `--formula`, with zero-based predicate indices and the operators `&`, `|`, and `!`. For full retrieval, provide a binary file of `N` consecutive fixed-length records in database row order. The capacity `K` must be a power of two up to 2048 and cover the number of matching rows.

```bash
python3 scripts/run.py --input /path/to/input --n "$N" \
    --domains "$DOMAINS" --formula "$FORMULA" \
    --payload /path/to/payload.bin --payload-length "$L" --capacity "$K" \
    --warmups 3 --repeats 10 --output results/run
```

Omit the three payload options to measure Match alone. For CPU pinning, supply `--server-cpus` and `--client-cpus`. The runner uses fresh PBM materials and pairs the Match, Index, and Retrieve online times by sample number. The output directory must be new. Formal sample times are printed as JSON lines.
