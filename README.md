# AUPIR

Reference implementation of **AUPIR — Boolean PIR for association-private retrieval of
unstructured objects**.

A client submits a Boolean predicate over index attributes and receives every matching
unstructured object. The servers learn neither which objects matched nor which condition
constrained which field, and the client's condition values stay private. The matching
stage is **IPBM (intent-private Boolean matching)** — a component of AUPIR, not a separate
protocol. The online stage selects BFS descriptors privately, runs one-use OCC-based
Batch PIR, and returns AES-GCM-encrypted objects.

## Repository layout

```
AUPIR/
├── query.py                 end-to-end entry point
├── requirements.txt
├── aupir/
│   ├── layout.py            block layout, locator, AES-GCM object recovery
│   ├── matching/            IPBM matching core
│   │   ├── compiler.py      two-slot encoding and public template
│   │   ├── engine.cpp       retrieval engine (C++)
│   │   ├── retrieval.h      descriptor OT, BFS encode, OCC bridge (C++)
│   │   ├── dcf_bit_eval.h   DCF MAC evaluator specialization (C++)
│   │   ├── transport.py     local two-process transport
│   │   ├── pipeline.py      end-to-end assembly (prepare / query)
│   │   ├── cli.py           command-line interface
│   │   ├── backend_worker.py
│   │   ├── build.py         builds engine / engine_validation / test_dcf_eval
│   │   ├── test_compiler.py
│   │   ├── test_protocol.py
│   │   └── test_dcf_eval.cpp
│   └── online/              AUPIR online stage
│       ├── full_server.cpp  full-protocol server (C++)
│       ├── session.py       client API and reusable local parties
│       ├── install.py       aligned encrypted object installation
│       ├── bfs.py           BFS descriptor encoding
│       ├── parameters.py    capacity / rank / OCC parameters
│       └── build.py         builds full_server and its backend copy
├── backend/                 two-server DPF/OCC resident backend
│   ├── backend.cpp
│   ├── build.sh             fetches and verifies dpf-cpp, then compiles
│   ├── dpf_cpp_secure_rng.patch
│   └── tests/test_ls_distribution.py
└── evaluation/              measurement scripts; not needed to build or run AUPIR
```

## Requirements

- Linux x86-64. The code uses POSIX sockets (`sys/socket.h`, `sys/random.h`),
  `<sys/resource.h>` and the Python `resource` module, so it does not build or run on
  macOS or Windows.
- GCC 13.x with C++17 and OpenMP.
- OpenSSL, `boost_system`, `boost_thread`, `boost_atomic`, `libgomp`.
- **Kunlun** DCF library (`DCFClient.h`, `DCFServer.cpp`, `libp2frpso_dcfverified.a`),
  exported as `KUNLUN_ROOT`.
- **Waldo** `fss-core` (libOTe with IKNP, `DPF-source`, libPSI, cryptoTools),
  exported as `WALDO_ROOT`.
- **Relic** (`librelic.so`), exported as `RELIC_ROOT`.
- Python 3.11+ with `cryptography` (`pip install -r requirements.txt`).

The three `*_ROOT` variables have no fallback: the build stops with an explicit message if
any is unset or does not contain a compiled dependency. dpf-cpp is the only external
source fetched automatically — `backend/build.sh` pins commit
`14bafa285845d5c4e5ab28b030283258aad67e48`, verifies the tarball SHA-256, applies
`dpf_cpp_secure_rng.patch`, and exits on any mismatch.

## Build

Run from the repository root, in this order — each step consumes the previous one's output.

```bash
python3 aupir/matching/build.py --validation   # engine, engine_validation, build_manifest.json
bash backend/build.sh                          # backend/build/<binary>, plus self-test
python3 aupir/online/build.py                  # aupir/online/build/full_server and its backend
```

Each step writes into its own `build/` directory and records the compiler command plus
source and binary hashes in a manifest; steps 2 and 3 reuse the dpf-cpp vendor tree under
`TMPDIR`. `engine_validation` is the share-exporting binary used by validation checks only —
the default `engine` cannot export shares.

## Run

```bash
python3 query.py --demo --output-dir /tmp/aupir-demo
```

The demo installs a small encrypted snapshot, runs one Boolean query over two local server
processes, and writes the recovered objects plus `result.json` (timings, per-server
metrics, communication volume). For your own data, use `--prepare-json` to install a
snapshot and then `--snapshot` with `--predicate-json` to query it.

## Tests

```bash
python3 -B -m unittest aupir.matching.test_compiler -v   # no binaries required
python3 -B -m unittest aupir.matching.test_protocol -v   # needs the build above
python3 -B -m unittest discover -s backend/tests -v
```

`test_compiler` checks the encoding mathematics only; `test_protocol` runs real
two-process queries and compares every recovered object against a plaintext oracle,
including zero-match, boundary and overflow cases.
