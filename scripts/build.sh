#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
jobs=${JOBS:-4}
deps="$root/.deps"
libote=${LIBOTE_SOURCE:-"$deps/libOTe"}
libote_build=${LIBOTE_BUILD:-"$libote/out/build/linux"}
libote_prefix=${LIBOTE_PREFIX:-"$libote/out/install/linux"}
spirit=${SPIRIT_SOURCE:-"$deps/SPIRIT"}
spirit_build=${SPIRIT_BUILD:-"$deps/spirit-build"}
build=${BUILD_DIR:-"$root/build"}

checkout() {
    local path=$1 url=$2 revision=$3
    if [[ ! -e "$path" ]]; then
        mkdir -p -- "$(dirname -- "$path")"
        git clone --no-checkout "$url" "$path"
        git -C "$path" checkout --detach "$revision"
    fi
    if [[ $(git -C "$path" rev-parse HEAD) != "$revision" ]]; then
        printf 'Unexpected dependency revision in %s. Expected %s.\n' "$path" "$revision" >&2
        return 1
    fi
}

checkout "$libote" https://github.com/osu-crypto/libOTe.git e8996e1779dca0a19877007675eed26803012336
if [[ ! -f "$libote_build/libOTe/liblibOTe.a" ]]; then
    git -C "$libote" submodule update --init --recursive
    cmake -S "$libote" -B "$libote_build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DLIBOTE_BUILD_DIR="$libote_build" -DOC_THIRDPARTY_INSTALL_PREFIX="$libote_prefix" \
        -DPARALLEL_FETCH="$jobs" -DSUDO_FETCH=OFF \
        -DFETCH_AUTO=ON -DENABLE_BOOST=ON -DFETCH_BOOST=ON \
        -DENABLE_SODIUM=ON -DFETCH_SODIUM=ON -DENABLE_KOS=ON -DENABLE_IKNP=ON -DENABLE_SIMPLESTOT_ASM=ON
    cmake --build "$libote_build" --target libOTe --parallel "$jobs"
fi
for feature in ENABLE_IKNP ENABLE_SIMPLESTOT_ASM; do
    if ! grep -Eq "^#define ${feature}([[:space:]]|$)" "$libote_build/libOTe/config.h"; then
        printf 'libOTe build must enable %s.\n' "$feature" >&2
        exit 1
    fi
done

checkout "$spirit" https://github.com/zhouzhangwalker/SPIRIT.git 7e4c114807d5a83ae5cbad17c514df1dbc32dfc3
if [[ ! -f "$spirit_build/lib/libSPIRIT.a" ]]; then
    cmake -S "$spirit" -B "$spirit_build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF -DSEAL_USE_INTEL_HEXL=ON
    cmake --build "$spirit_build" --target SPIRIT --parallel "$jobs"
fi

cmake -S "$root" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DlibOTe_DIR="$libote_build" -DCMAKE_PREFIX_PATH="$libote_prefix" \
    -DcryptoTools_DIR="$libote_build/cryptoTools" -Dcoproto_DIR="$libote_build/coproto/coproto" \
    -Dmacoro_DIR="$libote_build/macoro/macoro" \
    -DSPIRIT_SOURCE="$spirit" -DSPIRIT_BUILD="$spirit_build"
cmake --build "$build" --parallel "$jobs"
