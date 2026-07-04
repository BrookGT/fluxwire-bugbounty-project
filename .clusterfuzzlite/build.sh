#!/bin/bash -eu
# ClusterFuzzLite build for sandforge — standard fuzz/ layout.

cd "$SRC"

TARGETS=(
  elf_fuzzer
  pe_fuzzer
  der_fuzzer
  wasm_fuzzer
  manifest_fuzzer
  archive_fuzzer
  journal_fuzzer
  cbor_fuzzer
)

BIN_ARGS=()
for t in "${TARGETS[@]}"; do
  BIN_ARGS+=(--bin "$t")
done

cargo build \
  --release \
  --package sandforge-fuzz \
  --features libfuzzer \
  "${BIN_ARGS[@]}"

for t in "${TARGETS[@]}"; do
  cp "target/release/$t" "$OUT/$t"
  corpus_dir="fuzz/corpus/${t}"
  if [ -d "$corpus_dir" ]; then
    (cd "$corpus_dir" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
  fi
done
