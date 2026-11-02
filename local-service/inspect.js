#!/usr/bin/env node
/* Optional, detection-only helper: shells out to 7z/unrar/gpg's own listing commands to
 * confirm encryption and (for archives) list member names. Never attempts password testing. */

const { execFile } = require('child_process');
const path = require('path');

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout, stderr, err });
    });
  });
}

async function inspect(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.rar') {
    const r = await run('unrar', ['l', '-p-', filePath]);
    const unrarRefusedEncrypted = !r.ok && /encryption is not supported|wrong password/i.test(r.stdout + r.stderr);
    if (r.ok || unrarRefusedEncrypted) {
      console.log(r.stdout);
      console.log(unrarRefusedEncrypted || /encrypted/i.test(r.stdout) ? 'Archive appears encrypted (per unrar).' : 'No encryption indicator found by unrar.');
      return;
    }
    // unrar missing, or some other failure: 7-Zip can also read RAR archives, so fall back to it.
    const r2 = await run('7z', ['l', '-slt', '-pinspect-only-dummy', filePath]);
    const encryptedHeader = !r2.ok && /wrong password|cannot open encrypted archive/i.test(r2.stdout + r2.stderr);
    if (!r2.ok && !encryptedHeader) return console.log('Neither unrar nor 7z could read this file:\n' + (r.stderr || r.err) + '\n' + (r2.stderr || r2.err));
    console.log(r2.stdout);
    console.log((encryptedHeader || /Encrypted = \+/i.test(r2.stdout)) ? 'Archive appears encrypted (per 7z listing).' : 'No encryption indicator found by 7z.');
  } else if (ext === '.7z') {
    // A dummy -p<password> is required even just to *list* an archive with an encrypted
    // header - without it, 7z blocks waiting for an interactive password on stdin, which
    // would hang this script forever. If the header actually is encrypted, 7z fails with a
    // "wrong password" error - itself a reliable, prompt-free signal of encryption.
    const r = await run('7z', ['l', '-slt', '-pinspect-only-dummy', filePath]);
    const encryptedHeader = !r.ok && /wrong password|cannot open encrypted archive/i.test(r.stdout + r.stderr);
    if (!r.ok && !encryptedHeader) return console.log('7z not available or failed:\n' + (r.stderr || r.err));
    console.log(r.stdout);
    console.log((encryptedHeader || /Encrypted = \+/i.test(r.stdout)) ? 'Archive appears encrypted (per 7z listing).' : 'No encryption indicator found by 7z.');
  } else if (ext === '.gpg' || ext === '.asc' || ext === '.pgp') {
    // For symmetrically-encrypted data, --list-packets tries to decrypt the session key to
    // show full packet details, which fails without a passphrase (no TTY to prompt on here)
    // - but it still prints the useful part ("AES256.CFB encrypted data", "encrypted with N
    // passphrase(s)") to stderr before failing. The binary simply not being found is the only
    // case that's actually "not available"; any other outcome still carries real information.
    const r = await run('gpg', ['--batch', '--list-packets', filePath]);
    if (!r.ok && r.err && r.err.code === 'ENOENT') return console.log('gpg not available.');
    console.log((r.stdout + r.stderr).trim());
  } else {
    console.log(`No inspector configured for extension "${ext}". Supported: .rar, .7z, .gpg/.asc/.pgp`);
  }
}

const target = process.argv[2];
if (!target) {
  console.log('Usage: node inspect.js <file>');
  process.exit(1);
}
inspect(target);
