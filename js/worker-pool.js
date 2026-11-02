/* Self-contained Web Worker pool for password verification. The worker script is built at
   runtime from a Blob URL containing the *actual* source of the shared crypto functions
   (via Function.prototype.toString), so there is a single source of truth and no separate
   worker file to fetch - this is what lets the app run from a plain double-clicked
   index.html with no server and no bundler.
   Depends on (main thread globals): strToBytes, concatBytes, CRC32_TABLE, crc32, crc32Final,
   PDF_PAD, md5, rc4, sha1, AES_SBOX, AES_INV_SBOX, AES_RCON, aesGmul, aesKeyExpansion,
   aesAddRoundKey, aesInvSubBytes, aesInvShiftRows, aesInvMixColumns, aesDecryptBlock,
   aesEcbDecrypt,
   computeKeyR234, pdfPadPassword, checkUserPasswordR234, checkOwnerPasswordR234, bytesEqual,
   sha, hash2B, checkUserPasswordR56, checkOwnerPasswordR56, zipCryptoInitKeys,
   zipCryptoDecryptBytes, checkZipCryptoPassword, deriveAesKeyMaterial, checkWinZipAesPassword,
   officeUtf16LeBytes, officeU32leBytes, officeXorRepeating, officeDeriveStandardKey,
   officeCheckStandardPassword. */

function buildWorkerSource() {
  const fns = [
    strToBytes, concatBytes, aesCbcNoPadEncrypt, crc32, crc32Final, md5, rc4, sha1,
    aesGmul, aesKeyExpansion, aesAddRoundKey, aesInvSubBytes, aesInvShiftRows, aesInvMixColumns,
    aesDecryptBlock, aesEcbDecrypt,
    computeKeyR234, pdfPadPassword, checkUserPasswordR234, checkOwnerPasswordR234, bytesEqual,
    sha, hash2B, checkUserPasswordR56, checkOwnerPasswordR56,
    zipCryptoInitKeys, zipCryptoDecryptBytes, checkZipCryptoPassword,
    deriveAesKeyMaterial, checkWinZipAesPassword,
    officeUtf16LeBytes, officeU32leBytes, officeXorRepeating, officeDeriveStandardKey,
    officeCheckStandardPassword
  ].map(f => f.toString()).join('\n\n');

  const constants = `
const CRC32_TABLE = Uint32Array.from(${JSON.stringify(Array.from(CRC32_TABLE))});
const PDF_PAD = Uint8Array.from(${JSON.stringify(Array.from(PDF_PAD))});
const AES_SBOX = Uint8Array.from(${JSON.stringify(Array.from(AES_SBOX))});
const AES_INV_SBOX = Uint8Array.from(${JSON.stringify(Array.from(AES_INV_SBOX))});
const AES_RCON = Uint8Array.from(${JSON.stringify(Array.from(AES_RCON))});
`;

  const workerMain = `
let cancelled = false;

function indexToCandidate(index, charset, length) {
  const chars = new Array(length);
  for (let i = length - 1; i >= 0; i--) {
    chars[i] = charset[index % charset.length];
    index = Math.floor(index / charset.length);
  }
  return chars.join('');
}

async function testPdfCandidate(passwordStr, info) {
  const passwordBytes = strToBytes(passwordStr);
  if (info.R >= 5) {
    let ok = await checkUserPasswordR56(passwordBytes, info);
    if (!ok) ok = await checkOwnerPasswordR56(passwordBytes, info);
    return ok;
  }
  let ok = checkUserPasswordR234(passwordBytes, info);
  if (!ok) ok = checkOwnerPasswordR234(passwordBytes, info);
  return ok;
}

async function testZipCandidate(passwordStr, zipPayload) {
  const passwordBytes = strToBytes(passwordStr);
  if (zipPayload.aesInfo) {
    const result = await checkWinZipAesPassword(passwordBytes, zipPayload.target, zipPayload.data, zipPayload.aesInfo);
    return result.valid;
  }
  return checkZipCryptoPassword(passwordBytes, zipPayload.target, zipPayload.data);
}

function testOfficeCandidate(passwordStr, officeInfo) {
  // Deliberately synchronous and slow: officeCheckStandardPassword runs a mandatory
  // 50,000-round SHA-1 key derivation per candidate (ECMA-376 Standard encryption's own
  // brute-force resistance, not something to optimize away).
  return officeCheckStandardPassword(passwordStr, officeInfo);
}

async function testCandidate(format, candidate, payload) {
  if (format === 'pdf') return testPdfCandidate(candidate, payload);
  if (format === 'office') return testOfficeCandidate(candidate, payload);
  return testZipCandidate(candidate, payload);
}

self.onmessage = async function(ev) {
  const msg = ev.data;
  if (msg.type === 'cancel') { cancelled = true; return; }

  if (msg.type === 'bench') {
    cancelled = false;
    const start = performance.now();
    let count = 0;
    const probe = strToBytes('benchmark-probe-password');
    while (performance.now() - start < msg.durationMs) { md5(probe); count++; }
    self.postMessage({ type: 'benchResult', id: msg.id, count });
    return;
  }

  if (msg.type === 'search') {
    cancelled = false;
    const { chunkId, format, payload, mode } = msg;
    let tested = 0;
    const REPORT_EVERY = format === 'office' ? 1 : 200; // office is ~2-3/sec/worker (50,000-round KDF); report every candidate
    try {
      if (mode === 'dict') {
        for (const candidate of msg.candidates) {
          if (cancelled) break;
          const ok = await testCandidate(format, candidate, payload);
          tested++;
          if (ok) { self.postMessage({ type: 'found', chunkId, password: candidate, tested }); return; }
          if (tested % REPORT_EVERY === 0) self.postMessage({ type: 'progress', chunkId, tested });
        }
      } else { // mask mode
        for (let idx = msg.start; idx < msg.end; idx++) {
          if (cancelled) break;
          const candidate = indexToCandidate(idx, msg.charset, msg.length);
          const ok = await testCandidate(format, candidate, payload);
          tested++;
          if (ok) { self.postMessage({ type: 'found', chunkId, password: candidate, tested }); return; }
          if (tested % REPORT_EVERY === 0) self.postMessage({ type: 'progress', chunkId, tested });
        }
      }
      self.postMessage({ type: 'done', chunkId, tested });
    } catch (err) {
      self.postMessage({ type: 'error', chunkId, message: String(err && err.message || err) });
    }
  }
};
`;

  return constants + '\n' + fns + '\n' + workerMain;
}

let cachedWorkerUrl = null;
function getWorkerUrl() {
  if (cachedWorkerUrl) return cachedWorkerUrl;
  const blob = new Blob([buildWorkerSource()], { type: 'application/javascript' });
  cachedWorkerUrl = URL.createObjectURL(blob);
  return cachedWorkerUrl;
}

function createWorkerPool(n) {
  const url = getWorkerUrl();
  const workers = [];
  for (let i = 0; i < n; i++) workers.push(new Worker(url));
  return {
    workers,
    terminate() { for (const w of workers) w.terminate(); }
  };
}

/* ---------- Candidate space helpers ---------- */

function maskKeyspaceSize(charsetLen, length) { return Math.pow(charsetLen, length); }

function splitRange(total, n) {
  const ranges = [];
  const base = Math.floor(total / n);
  let start = 0;
  for (let i = 0; i < n; i++) {
    const extra = i < (total % n) ? 1 : 0;
    const size = base + extra;
    ranges.push([start, start + size]);
    start += size;
  }
  return ranges;
}

function splitList(list, n) {
  const chunks = Array.from({ length: n }, () => []);
  for (let i = 0; i < list.length; i++) chunks[i % n].push(list[i]);
  return chunks;
}

/**
 * Starts a finite password search (dictionary list, or a bounded charset^length mask) across
 * a worker pool. Returns { promise, cancel }; promise resolves to
 * { found: bool, password?, cancelled?, tested, elapsedMs }.
 */
function runPasswordSearch({ format, payload, mode, dict, charset, length, numWorkers, onProgress }) {
  let cancelFn = () => {};
  const promise = new Promise((resolve) => {
    const n = Math.max(1, numWorkers | 0);
    const pool = createWorkerPool(n);
    const start = performance.now();
    let totalTested = 0;
    let finished = 0;
    let settled = false;
    const perChunkTested = new Array(n).fill(0);

    function finishAll(result) {
      if (settled) return;
      settled = true;
      for (const w of pool.workers) w.postMessage({ type: 'cancel' });
      setTimeout(() => pool.terminate(), 50);
      resolve({ ...result, tested: totalTested, elapsedMs: performance.now() - start });
    }
    cancelFn = () => finishAll({ found: false, cancelled: true });

    pool.workers.forEach((w, chunkId) => {
      w.onmessage = (ev) => {
        const msg = ev.data;
        if (msg.type === 'progress' || msg.type === 'done' || msg.type === 'found') {
          totalTested += (msg.tested - perChunkTested[chunkId]);
          perChunkTested[chunkId] = msg.tested;
          if (onProgress) onProgress(totalTested);
        }
        if (msg.type === 'found') finishAll({ found: true, password: msg.password });
        else if (msg.type === 'error') { finished++; if (finished === n) finishAll({ found: false, error: msg.message }); }
        else if (msg.type === 'done') { finished++; if (finished === n) finishAll({ found: false }); }
      };
    });

    if (mode === 'dict') {
      const chunks = splitList(dict, n);
      pool.workers.forEach((w, i) => w.postMessage({ type: 'search', chunkId: i, format, payload, mode: 'dict', candidates: chunks[i] }));
    } else {
      const total = maskKeyspaceSize(charset.length, length);
      const ranges = splitRange(total, n);
      pool.workers.forEach((w, i) => w.postMessage({ type: 'search', chunkId: i, format, payload, mode: 'mask', charset, length, start: ranges[i][0], end: ranges[i][1] }));
    }
  });
  return { promise, cancel: () => cancelFn() };
}

if (typeof module !== 'undefined') module.exports = { buildWorkerSource, createWorkerPool, runPasswordSearch, maskKeyspaceSize, splitRange, splitList };
