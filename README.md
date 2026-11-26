# AUPIR

Reference implementation of **AUPIR — Boolean PIR for association-private retrieval of
unstructured objects**, accompanying the paper of the same title.

AUPIR retrieves whole unstructured objects whose index attributes satisfy a Boolean
predicate, while hiding (i) which objects matched, (ii) which condition constrained which
field, and (iii) what the client's intent was. The matching stage is
**IPBM (intent-private Boolean matching)**; it is a component of AUPIR, not a separate
protocol. The online stage performs private BFS-descriptor selection, one-use OCC-based
Batch PIR, and authenticated AES-GCM object recovery.

## Repository layout

```
AUPIR/
├── query.py                 default end-to-end entry point
├── requirements.txt
├── aupir/
│   ├── layout.py            block layout, locator, AES-GCM object recovery
│   ├── matching/            IPBM matching core
│   │   ├── compiler.py      two-slot encoding, public template, private spec
│   │   ├── engine.cpp       default retrieval engine (C++)
│   │   ├── retrieval.h      descriptor OT, BFS encode, OCC bridge (C++)
│   │   ├── dcf_bit_eval.h   Kunlun DCF MAC evaluator specialization (C++)
│   │   ├── transport.py     local two-process transport pair
│   │   ├── pipeline.py      end-to-end assembly (prepare / query)
│   │   ├── backend_worker.py
│   │   ├── cli.py
│   │   ├── build.py         builds engine / engine_validation / test_dcf_eval
│   │   ├── test_compiler.py compiler-level tests (no binaries needed)
│   │   ├── test_protocol.py two-process protocol regression tests
│   │   └── test_dcf_eval.cpp
│   └── online/              AUPIR online stage
│       ├── full_server.cpp  full-protocol server (C++, Algorithm 2)
│       ├── session.py       client API and reusable local parties
│       ├── install.py       aligned encrypted object installation
│       ├── bfs.py           BFS descriptor encoding
│       ├── parameters.py    capacity / rank / OCC parameter rules
│       └── build.py         builds full_server and its backend copy
├── backend/                 two-server DPF/OCC resident backend
│   ├── backend.cpp
│   ├── build.sh             fetches plus verifies dpf-cpp, then compiles
│   ├── dpf_cpp_secure_rng.patch
│   └── tests/test_ls_distribution.py
└── evaluation/
    ├── final/               final-construction validation and timing
    └── baseline/            independent paired-process baseline
```

## Requirements

- Linux x86-64 (the code uses `sys/socket.h`, `sys/random.h`, `sys/resource.h`,
  and the Python `resource` module; it does not build or run on macOS/Windows).
- GCC 13.x with C++17 and OpenMP. Reported measurements used a Xeon Gold 5218R
  at 2.10 GHz, 40 logical cores, 128-bit security.
- OpenSSL, `boost_system`, `boost_thread`, `boost_atomic`, `libgomp`.
- **Kunlun** DCF library — `DCFClient.h`, `DCFServer.cpp`,
  `libp2frpso_dcfverified.a`; exported as `KUNLUN_ROOT`.
- **Waldo** `fss-core` — libOTe (IKNP), `DPF-source`, libPSI, cryptoTools;
  exported as `WALDO_ROOT`.
- **Relic** — `librelic.so`; exported as `RELIC_ROOT`.
- Python 3.11+ with `cryptography` (`pip install -r requirements.txt`).

`KUNLUN_ROOT`, `WALDO_ROOT` and `RELIC_ROOT` have no fallback: the build stops with an
explicit message if any of them is unset or does not contain a compiled dependency.

The only external source that is fetched automatically is dpf-cpp. `backend/build.sh`
pins commit `14bafa285845d5c4e5ab28b030283258aad67e48`, verifies the tarball SHA-256
`06442f991920e1fba98d4a5ee35bda9daf8d650e5926f091b4188bae2f652439`, applies
`dpf_cpp_secure_rng.patch` (OpenSSL `RAND_bytes` for DPF freshness), and exits on any
mismatch.

## Build

Run from the repository root, in this order. Each step consumes the artifact of the
previous one.

```bash
# 1) matching core: engine, engine_validation, test_dcf_eval, build_manifest.json
python3 aupir/matching/build.py --validation

# 2) resident backend: backend/build/backend (+ self-test)
bash backend/build.sh

# 3) online stage: aupir/online/build/full_server and its backend copy
python3 aupir/online/build.py
```

`build.py` writes `build_manifest.json` recording the exact compiler command and the
SHA-256 of every input and output; steps 2 and 3 reuse the warm `/tmp/two-server-dpf-cpp`
vendor tree. `engine_validation` (built with `--validation`) is the share-exporting binary
used only by validation checks; the default `engine` has no share-export capability.

## Quick start

```bash
python3 query.py --demo --output-dir /tmp/aupir-demo
```

The demo prepares a small encrypted snapshot, runs one Boolean query over two local
server processes, and writes the recovered objects plus `result.json` (timings,
per-server metrics, communication volume).

## Tests

```bash
# compiler-level mathematics, no binaries required
python3 -B -m unittest aupir.matching.test_compiler -v

# two-process protocol regression; needs steps 1-3 above
python3 -B -m unittest aupir.matching.test_protocol -v

# backend distribution/self-test regression
python3 -B -m unittest discover -s backend/tests -v
```

## Evaluation harnesses

```bash
# end-to-end validation and timing of the final construction
python3 evaluation/final/run.py --out /tmp/aupir-final --repeats 11 --warmups 2

# independent paired-process baseline (build the worker first)
python3 evaluation/baseline/build.py
python3 evaluation/baseline/run.py
```

`evaluation/final/run.py` optionally cross-checks each workload against a frozen
reference result set in `artifacts/baseline_20261114/results.json`. That file is part of
the internal verification record and is not distributed; when it is absent, the harness
skips the historical cross-check and still validates every query vector against the
plaintext oracle.

## Code-to-paper map

| Path | Paper |
| --- | --- |
| `aupir/matching/compiler.py` | Sec. V-B: two-slot encoding, public template |
| `aupir/matching/engine.cpp`, `retrieval.h`, `dcf_bit_eval.h` | Sec. V-B–V-C: DCF evaluation, IKNP, Beaver triples, CountOT |
| `backend/backend.cpp` | Sec. V-C: two-server DPF/OCC backend, masking before OCC |
| `aupir/online/full_server.cpp` | Sec. IV-B–IV-C, Algorithm 2 |
| `aupir/online/install.py`, `bfs.py`, `parameters.py`, `session.py` | Sec. IV-B–IV-C, Sec. VI-B |
| `aupir/layout.py` | Sec. VI-B: block layout, AES-GCM recovery |
| `aupir/matching/pipeline.py`, `cli.py`, `transport.py`, `query.py` | end-to-end assembly, local process pair |
| `evaluation/final/` | Sec. VII: reported timings and communication volumes |
| `evaluation/baseline/` | Sec. VII: baseline comparison |

## Artifacts and hygiene

- Compiled binaries (`aupir/matching/engine`, `engine_validation`, `test_dcf_eval`,
  `aupir/online/build/*`, `backend/build/*`, `evaluation/baseline/worker`) are build
  outputs and are not distributed.
- `build_manifest.json`, `validation_build_manifest.json` and `aupir/online/build/manifest.json`
  are generated locally by the build steps above; they embed absolute paths of the
  building host and should never be committed.
- A `--clean` / `--clean-build-only` flag on `backend/build.sh` removes the vendor cache
  or the build directory respectively.

## Limitations

- The local deployment fixture is unauthenticated loopback TCP. A real deployment must
  supply the authenticated confidential channels assumed by the paper.
- Each server pair runs as two separate processes on one host; no multi-host transport
  or TLS layer is included.
- The baseline harness reproduces the paired-process comparison only; it does not
  implement a full dictionary-based retrieval system.
