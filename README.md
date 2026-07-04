# Sandforge

Sandforge is a **sandbox artifact verification** library for edge CI pipelines.
It parses untrusted build artifacts before execution: ELF64 binaries, PE/COFF
images, WebAssembly modules, X.509 DER certificates, SMNF policy manifests,
ARSF file archives, CBOR attestation bundles, and binary verification journals.

This is **not** an observability or telemetry stack — it targets binary
format verification at the artifact boundary.

## Modules

| Module | Role |
|--------|------|
| `elf` | ELF64 headers, program/section tables, notes |
| `pe` | PE/COFF headers, sections, import table |
| `wasm` | WebAssembly module sections |
| `der` | ASN.1 DER TLV and certificate skeleton |
| `manifest` | SMNF sandbox policy manifests |
| `archive` | ARSF multi-file archives |
| `journal` | JRN2 verification script driver |
| `cbor` | attestation record decoder |
| `pool` | blob store, tickets, scratch buffers |
| `verify` | cross-format probe helpers |

## Layout

```text
sandforge-core/     library source
fuzz/               libFuzzer harnesses + corpora
.clusterfuzzlite/   hermetic build entry point
vendor/             offline dependencies
```

## Build

```bash
cargo check --workspace
cargo test -p sandforge-core
```

## Fuzzing

Eight harnesses under `fuzz/fuzz_targets/`. ClusterFuzzLite runs
`.clusterfuzzlite/build.sh`.

## License

MIT OR Apache-2.0
