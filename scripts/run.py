import argparse
from array import array
from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import resource
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
TRAFFIC = (
    "pir_upload_bytes",
    "pir_download_bytes",
    "oprf_upload_bytes",
    "oprf_download_bytes",
)
LIBC = ctypes.CDLL(None, use_errno=True)


def check(condition, message):
    if not condition:
        raise ValueError(message)


def cpu_set(spec):
    if spec is None:
        return None
    cpus = set()
    try:
        for item in spec.split(","):
            first, sep, last = item.partition("-")
            start, stop = int(first), int(last) if sep else int(first)
            if not 0 <= start <= stop < os.cpu_count():
                raise ValueError
            cpus.update(range(start, stop + 1))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Expected a CPU list such as 4-12 or 4,6,8"
        ) from exc
    if not cpus <= os.sched_getaffinity(0):
        raise argparse.ArgumentTypeError("CPU list includes unavailable logical CPUs")
    return cpus


def command(binary, action=None, **options):
    args = [str(binary)]
    if action is not None:
        args.append(action)
    for key, value in options.items():
        args.extend(("--" + key.replace("_", "-"), str(value)))
    return args


@contextmanager
def child(cmd, log, cpus, threads=1, memory=None):
    parent = os.getpid()

    def setup():
        if LIBC.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            os._exit(125)
        if cpus is not None:
            os.sched_setaffinity(0, cpus)
        if memory is not None:
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

    env = dict(os.environ, OMP_NUM_THREADS=str(threads), OMP_DYNAMIC="FALSE")
    with log.open("xb") as stream:
        proc = subprocess.Popen(
            cmd, stdout=stream, stderr=stream, env=env, preexec_fn=setup
        )
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def records(log):
    with log.open("rb") as stream:
        return [
            json.loads(line)
            for line in stream
            if line.startswith(b"{") and line.endswith(b"\n")
        ]


def record(log):
    rows = records(log)
    check(rows, f"No result in {log}")
    return rows[-1]


def wait(proc, log, timeout):
    check(proc.wait(timeout=timeout) == 0, f"Process exit {proc.returncode}. See {log}")


def wait_record(proc, log, predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in records(log):
            if predicate(row):
                return row
        check(
            proc.poll() is None, f"Server exited before the expected result. See {log}"
        )
        time.sleep(0.025)
    raise TimeoutError(f"Server timed out. See {log}")


def run(cmd, log, cpus, timeout, threads=1, memory=None):
    with child(cmd, log, cpus, threads, memory) as proc:
        wait(proc, log, timeout)
    return record(log)


def ports(width):
    for _ in range(100):
        base = 22000 + secrets.randbelow(10000)
        with socket.socket() as first, socket.socket() as second:
            try:
                first.bind(("127.0.0.1", base))
                if width == 2:
                    second.bind(("127.0.0.1", base + 1))
                return base
            except OSError:
                continue
    raise OSError("No free loopback port range")


def pair(binary, role, options, log_dir, label, args, bitmap=None):
    server_log = log_dir / f"{label}-server.log"
    client_log = log_dir / f"{label}-client.log"
    options = dict(options, port=ports(2 if role else 1))
    client = dict(options, out=bitmap) if bitmap is not None else options
    memory = args.memory_budget_gib << 30
    deadline = time.monotonic() + args.timeout
    with child(
        command(binary, role + "server", **options),
        server_log,
        args.server_cpus,
        memory=memory,
    ) as server:
        with child(
            command(binary, role + "client", **client),
            client_log,
            args.client_cpus,
            memory=memory,
        ) as client_proc:
            while time.monotonic() < deadline:
                s, c = server.poll(), client_proc.poll()
                check(
                    s in (None, 0) and c in (None, 0),
                    f"PBM role failure. See {server_log} and {client_log}",
                )
                if s == c == 0:
                    sent, recv = record(server_log), record(client_log)
                    check(
                        (sent["sent"], sent["received"])
                        == (recv["received"], recv["sent"]),
                        "PBM wire counters differ",
                    )
                    return recv
                time.sleep(0.015)
    raise TimeoutError(f"PBM timed out. See {server_log} and {client_log}")


def truth(args):
    database = args.input / "database.u64"
    query = (args.input / "query.u64").read_bytes()
    check(
        len(query) == 8 * len(args.domains)
        and database.stat().st_size == 8 * args.n * len(args.domains),
        "Incorrect database or query length",
    )
    digest = sha256()
    predicates = []
    with database.open("rb") as source:
        for i, (value,) in enumerate(struct.iter_unpack("<Q", query)):
            raw = source.read(args.n * 8)
            check(len(raw) == args.n * 8, "Incomplete attribute column")
            digest.update(raw)
            column = array("Q")
            column.frombytes(raw)
            check(
                value < 1 << 32 and max(column) < 1 << 32,
                "Attributes and query must fit in 32 bits",
            )
            check(
                len(set(column)) == args.domains[i], f"Wrong domain size for column {i}"
            )
            predicates.append(
                int.from_bytes(bytes(v == value for v in column), "little")
            )
        check(not source.read(1), "Trailing bytes in database")

    stack = []
    ones = int.from_bytes(b"\x01" * args.n, "little")
    for token in args.formula:
        if token.isascii() and token.isdecimal():
            col = int(token)
            check(col < len(predicates), f"Invalid predicate index {token}")
            stack.append(predicates[col])
        elif token == "!" and stack:
            stack[-1] ^= ones
        elif token in ("&", "|") and len(stack) >= 2:
            right, left = stack.pop(), stack.pop()
            stack.append(left & right if token == "&" else left | right)
        else:
            raise ValueError("Invalid postfix formula")
    check(len(stack) == 1, "Invalid postfix formula")
    rows = [
        i for i, matched in enumerate(stack[0].to_bytes(args.n, "little")) if matched
    ]
    bitmap = bytearray((args.n + 7) // 8)
    for row in rows:
        bitmap[row // 8] |= 1 << (row % 8)
    return bitmap, rows, digest.hexdigest()


def measure_match(args, logs, pbm, expected, database_id):
    slots = args.warmups + args.repeats
    materials = args.output / "materials"
    options = dict(
        n=args.n,
        domains=",".join(map(str, args.domains)),
        formula=",".join(args.formula),
        materials=materials,
        database_id=database_id,
        pool_id=secrets.token_hex(16),
        slots=slots,
        scheme="domain",
        packed=1,
        fused=1,
        fast_input=1,
        kernel="avx2",
        layout="layer",
        map="lookup",
        mode="fresh",
    )
    memory = args.memory_budget_gib << 30
    run(
        command(pbm, "dealer", **options),
        logs / "dealer.log",
        args.server_cpus,
        args.timeout,
        memory=memory,
    )
    options["data"] = args.input
    pair(pbm, "ot-", options, logs, "randexpand", args)
    samples, bitmaps = [], []
    for slot in range(slots):
        bitmap = args.output / f"match-{slot}.bits"
        result = pair(
            pbm,
            "",
            dict(options, slot=slot, query_id=slot + 1),
            logs,
            f"match-{slot}",
            args,
            bitmap,
        )
        check(
            bitmap.read_bytes() == expected,
            "PBM bitmap differs from the plaintext evaluation",
        )
        check(
            all(
                (materials / role / f"{slot}.used").is_file()
                for role in ("server", "client")
            ),
            "Missing PBM material consumption marker",
        )
        samples.append(
            dict(
                match_ms=result["online_total_ms"],
                match_bytes=result["sent"] + result["received"],
            )
        )
        bitmaps.append(bitmap)
    return samples, bitmaps


def verify_recovered(path, payload, length, rows):
    raw = path.read_bytes()
    stride = length + 8
    check(
        len(raw) == 8 + len(rows) * stride
        and struct.unpack_from(">Q", raw)[0] == len(rows),
        "Malformed recovery output",
    )
    with payload.open("rb") as source:
        for at, row in zip(range(8, len(raw), stride), rows):
            check(struct.unpack_from(">Q", raw, at)[0] == row, "Wrong recovered row")
            source.seek(row * length)
            check(
                source.read(length) == raw[at + 8 : at + stride],
                f"Incorrect payload for row {row}",
            )


def measure_retrieval(args, logs, retrieval, rows, bitmaps, samples):
    state = args.output / "db-state"
    public = args.output / "pp.bin"
    aux = args.output / "aux.bin"
    base = dict(n=args.n, payload_length=args.payload_length, capacity=args.capacity)
    memory = args.memory_budget_gib << 30
    run(
        command(
            retrieval,
            "prepare-payload",
            **base,
            payload_file=args.payload,
            db_state=state,
        ),
        logs / "prepare-payload.log",
        args.server_cpus,
        args.timeout,
        memory=memory,
    )
    common = dict(base, public_params=public)
    run(
        command(
            retrieval,
            "prepare-spirit",
            **common,
            encrypted_db=state / "payload.enc",
            aux=aux,
            memory_budget_gib=args.memory_budget_gib,
        ),
        logs / "prepare-spirit.log",
        args.server_cpus,
        args.timeout,
        args.server_threads,
        memory,
    )

    port = ports(2)
    endpoints = dict(common, pir_port=port, oprf_port=port + 1)
    opts = dict(
        endpoints, db_state=state, aux=aux, bind="127.0.0.1", queries=len(samples)
    )
    server_log = logs / "retrieval-server.log"
    with child(
        command(retrieval, "serve", **opts),
        server_log,
        args.server_cpus,
        args.server_threads,
        memory,
    ) as server:
        wait_record(server, server_log, lambda r: r.get("ready"), args.timeout)
        for seq, (bitmap, sample) in enumerate(zip(bitmaps, samples)):
            recovered = args.output / f"recovered-{seq}.bin"
            client_opts = dict(
                endpoints,
                host="127.0.0.1",
                match_bitmap=bitmap,
                output=recovered,
                extract_mode="parallel",
                crypto_mode="reuse",
                client_extract_threads=args.client_threads,
            )
            client = run(
                command(retrieval, "query", **client_opts),
                logs / f"retrieval-{seq}.log",
                args.client_cpus,
                args.timeout,
                args.client_threads,
                memory,
            )
            result = wait_record(
                server, server_log, lambda r: r.get("seq") == seq, args.timeout
            )
            check(
                not result.get("server_failed"),
                f"Retrieve server reported a failure. See {server_log}",
            )
            wire = [client[f] for f in TRAFFIC]
            check(
                wire == [result[f] for f in TRAFFIC]
                and all(x > 0 for x in wire)
                and wire[2:] == [args.capacity * 32] * 2
                and sum(wire) == client["online_total_bytes"],
                "Retrieve wire counters differ",
            )
            check(
                (
                    client["N"],
                    client["payload_len"],
                    client["capacity_K"],
                    client["t"],
                    client["recovered_count"],
                )
                == (args.n, args.payload_length, args.capacity, len(rows), len(rows)),
                "Retrieve output has the wrong dimensions",
            )
            verify_recovered(recovered, args.payload, args.payload_length, rows)
            ms = client["total_parallel_wall_ms"]
            sample.update(
                retrieve_ms=ms,
                retrieve_bytes=sum(wire),
                full_ms=sample["match_ms"] + sample["index_ms"] + ms,
            )
        wait(server, server_log, args.timeout)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Measure one Boolean-PIR configuration on loopback."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument(
        "--domains",
        type=lambda value: [int(x) for x in value.split(",")],
        required=True,
    )
    parser.add_argument(
        "--formula",
        type=lambda value: [x.strip() for x in value.split(",")],
        required=True,
    )
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--payload-length", type=int)
    parser.add_argument("--capacity", type=int)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--server-cpus", type=cpu_set)
    parser.add_argument("--client-cpus", type=cpu_set)
    parser.add_argument("--server-threads", type=int, default=8)
    parser.add_argument("--client-threads", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--memory-budget-gib", type=int, default=78)
    args = parser.parse_args()
    for key in ("input", "payload", "output", "build_dir"):
        if (path := getattr(args, key)) is not None:
            setattr(args, key, path.resolve())
    return args


def main():
    os.umask(0o077)
    args = parse_args()
    check(
        sys.byteorder == "little" and array("Q").itemsize == 8,
        "Expected a little-endian host",
    )
    check(
        1 <= args.n <= 2**20
        and 1 <= len(args.domains) <= 10
        and all(1 <= d <= args.n for d in args.domains),
        "Invalid database or domain size",
    )
    check(
        args.warmups >= 0 and args.repeats >= 1 and args.warmups + args.repeats <= 128,
        "Expected at most 128 total samples, with at least one formal sample",
    )
    check(
        1 <= args.server_threads
        and 1 <= args.client_threads <= 32
        and args.timeout > 0
        and args.memory_budget_gib > 0,
        "Invalid resource settings",
    )
    pbm = args.build_dir / "frozen/pbm_frozen"
    check(pbm.is_file(), f"Missing binary {pbm}. Build the project first")
    full = args.payload is not None
    check(
        full == (args.payload_length is not None) == (args.capacity is not None),
        "Supply --payload, --payload-length and --capacity together",
    )
    expected, rows, database_id = truth(args)
    if full:
        check(
            1 <= args.payload_length <= 8192
            and 1 <= args.capacity <= min(2048, args.n)
            and args.capacity.bit_count() == 1
            and max(2, args.capacity) <= args.n
            and args.payload.stat().st_size == args.n * args.payload_length,
            "Invalid payload length, capacity or file size",
        )
        check(len(rows) <= args.capacity, "Capacity is smaller than the match count")
        index, retrieval = (
            args.build_dir / "retrieval_bench" / name
            for name in ("index_benchmark", "retrieval")
        )
        check(
            index.is_file() and retrieval.is_file(),
            "Build the Index and Retrieve binaries first",
        )

    args.output.mkdir(parents=True)
    logs = args.output / "logs"
    logs.mkdir()
    samples, bitmaps = measure_match(args, logs, pbm, expected, database_id)
    if full:
        for seq, (bitmap, sample) in enumerate(zip(bitmaps, samples)):
            result = run(
                [str(index), str(bitmap), str(args.n)],
                logs / f"index-{seq}.log",
                args.client_cpus,
                args.timeout,
            )
            check(
                result["rows"] == rows, "Index output differs from verified PBM indices"
            )
            sample["index_ms"] = result["index_extract_ms"]
        measure_retrieval(args, logs, retrieval, rows, bitmaps, samples)
    for sample in samples:
        check(
            all(
                math.isfinite(value) and value >= 0
                for key, value in sample.items()
                if key.endswith("_ms")
            ),
            "Invalid online time",
        )
    for i, sample in enumerate(samples[args.warmups :]):
        print(
            json.dumps(
                dict(sample_no=i, matched_count=len(rows), **sample), allow_nan=False
            )
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(str(exc)) from exc
