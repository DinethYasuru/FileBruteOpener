/* Office Open XML (.docx/.xlsx/.pptx) password verification for the "Standard" (ECMA-376
 * §2.3.4.6-2.3.4.9, a.k.a. "CryptoAPI") encryption scheme - the one actually produced by
 * LibreOffice (and by Office itself when legacy-compatible encryption is used). The newer
 * "Agile" scheme (version 4.4, Office 2010+'s own default) is detected but not yet verified -
 * see the capability matrix.
 * Depends on: utils.js (concatBytes, u32le, u16le), sha1.js, aes.js (aesEcbDecrypt), cfb.js. */

function officeUtf16LeBytes(str) {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = (code >> 8) & 0xff;
  }
  return out;
}

function officeU32leBytes(n) {
  return Uint8Array.from([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
}

function officeXorRepeating(data, byteVal, totalLen) {
  const out = new Uint8Array(totalLen).fill(byteVal);
  for (let i = 0; i < data.length && i < totalLen; i++) out[i] = data[i] ^ byteVal;
  return out;
}

/** ECMA-376 Standard key derivation (§2.3.4.7): SHA-1, salt+password, then a fixed 50,000
 * iterations, then an HMAC-like 0x36/0x5C padding trick to stretch the 20-byte SHA-1 output
 * up to whatever key size is needed (AES-128/192/256 all fit within the resulting 40 bytes). */
function officeDeriveStandardKey(password, salt, keySizeBits) {
  const ITER_COUNT = 50000;
  let h = sha1(concatBytes(salt, officeUtf16LeBytes(password)));
  for (let i = 0; i < ITER_COUNT; i++) h = sha1(concatBytes(officeU32leBytes(i), h));
  const hFinal = sha1(concatBytes(h, officeU32leBytes(0)));
  const x1 = sha1(officeXorRepeating(hFinal, 0x36, 64));
  const x2 = sha1(officeXorRepeating(hFinal, 0x5c, 64));
  return concatBytes(x1, x2).slice(0, keySizeBits / 8);
}

const OFFICE_ALG_IDS = { 0x660E: 128, 0x660F: 192, 0x6610: 256 };

/** Parses the EncryptionInfo stream for the "Standard" scheme (ECMA-376 §2.3.4.5-6). */
function parseOfficeEncryptionInfoStandard(info) {
  let off = 4; // versionMajor/versionMinor already consumed by the caller
  off += 4; // EncryptionHeaderFlags (duplicated inside the header itself; not needed again)
  const headerSize = u32le(info, off); off += 4;
  const headerStart = off;
  const flags = u32le(info, off); off += 4;
  off += 4; // sizeExtra
  const algId = u32le(info, off); off += 4;
  const algIdHash = u32le(info, off); off += 4;
  const keySizeField = u32le(info, off); off += 4;
  off = headerStart + headerSize; // skip providerType/reserved1/reserved2/cspName - not needed

  const saltSize = u32le(info, off); off += 4;
  const salt = info.slice(off, off + 16); off += 16;
  const encryptedVerifier = info.slice(off, off + 16); off += 16;
  const verifierHashSize = u32le(info, off); off += 4;
  const isAes = (algId & 0xFF00) === 0x6600;
  const verifierHashLen = isAes ? 32 : 20;
  const encryptedVerifierHash = info.slice(off, off + verifierHashLen);

  const keySizeBits = OFFICE_ALG_IDS[algId] || (keySizeField || 40);
  return { algId, algIdHash, isAes, keySizeBits, saltSize, salt, encryptedVerifier, verifierHashSize, encryptedVerifierHash };
}

function officeCheckStandardPassword(password, parsed) {
  if (!parsed.isAes) return null; // RC4 CryptoAPI: not implemented, see capability matrix
  const key = officeDeriveStandardKey(password, parsed.salt, parsed.keySizeBits);
  const verifier = aesEcbDecrypt(key, parsed.encryptedVerifier);
  const expectedHash = sha1(verifier);
  const decryptedVerifierHash = aesEcbDecrypt(key, parsed.encryptedVerifierHash);
  const verifierHash = decryptedVerifierHash.slice(0, 20);
  for (let i = 0; i < 20; i++) if (expectedHash[i] !== verifierHash[i]) return false;
  return true;
}

/** Parses an encrypted Office Open XML file's CFB container and EncryptionInfo stream.
 * Returns null if this isn't a CFB container, or doesn't carry the expected streams. */
function extractOfficeEncryptionInfo(bytes) {
  const cfb = cfbOpen(bytes);
  if (!cfb) return null;
  const info = cfb.readStream('EncryptionInfo');
  const pkg = cfb.readStream('EncryptedPackage');
  if (!info || !pkg) return null;

  const versionMajor = u16le(info, 0);
  const versionMinor = u16le(info, 2);
  if (versionMajor === 4 && versionMinor === 4) {
    return { scheme: 'agile', versionMajor, versionMinor };
  }
  if (versionMinor === 2) {
    const parsed = parseOfficeEncryptionInfoStandard(info);
    return { scheme: 'standard', versionMajor, versionMinor, ...parsed };
  }
  return { scheme: 'unknown', versionMajor, versionMinor };
}

async function verifyOfficePassword(bytes, password) {
  const parsed = extractOfficeEncryptionInfo(bytes);
  if (!parsed) return { applicable: false };
  if (parsed.scheme !== 'standard') {
    return { applicable: true, scheme: parsed.scheme, valid: null, note: 'Detection only for this encryption scheme.' };
  }
  const valid = officeCheckStandardPassword(password, parsed);
  if (valid === null) return { applicable: true, scheme: 'standard', valid: null, note: 'RC4 CryptoAPI not implemented.' };
  return { applicable: true, scheme: 'standard', keyBits: parsed.keySizeBits, valid };
}

if (typeof module !== 'undefined') {
  module.exports = {
    extractOfficeEncryptionInfo, verifyOfficePassword, officeCheckStandardPassword,
    officeDeriveStandardKey, parseOfficeEncryptionInfoStandard
  };
}
