# WASM source

`md5.c` is the freestanding C source compiled to the WASM binary embedded (as base64) in
`js/md5-wasm.js`. It's not loaded or executed at runtime - the compiled output is what ships -
but it's kept here so the binary blob isn't a black box: anyone can read exactly what it does
and recompile it themselves.

## Rebuilding

```
clang --target=wasm32 -O3 -nostdlib -Wl,--no-entry -Wl,--export=md5 -Wl,--export=get_buffer \
  -Wl,--allow-undefined -o md5.wasm md5.c
node -e "console.log(require('fs').readFileSync('md5.wasm').toString('base64'))"
```

Paste the output into `MD5_WASM_BASE64` in `js/md5-wasm.js`.

## Validation before trusting a rebuild

Before swapping in a new build, re-run it against both block-boundary edge cases and a large
batch of random inputs compared to a trusted reference (e.g. Node's `crypto.createHash('md5')`)
- the same way the current binary was checked before being embedded. A WASM miscompile or a
bug in `md5.c` would silently corrupt every password check that uses it; this one was only
trusted after thousands of random-length trials matched Node's crypto module exactly, plus
every MD5 block-boundary edge case (54-65 bytes, 119-121 bytes).
