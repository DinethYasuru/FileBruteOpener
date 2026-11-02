#!/usr/bin/env node
/* Generates real encrypted sample files for the formats the browser app can only detect,
 * not verify (RAR, 7z, Office Open XML, GPG) - by shelling out to the actual tools that
 * create those formats, each with a known password you can then try against the app's
 * identification panel (and, for RAR/7z/GPG, against local-service/inspect.js).
 *
 * This mirrors what js/generator.js does for PDF/ZIP inside the browser, but these four
 * formats need their real encoder installed locally - there's no pure-JS way to create them.
 *
 * Usage: node generate-samples.js [outputDir] [password]
 * Requires (whichever are installed - missing ones are skipped, not fatal):
 *   gpg   - GPG/OpenPGP symmetric encryption
 *   7z    - 7-Zip (p7zip-full / 7zip package)
 *   rar   - RAR archiver (non-free, from the multiverse/universe repo)
 *   soffice + python3-uno - LibreOffice headless, for Office Open XML (.docx/.xlsx/.pptx)
 */

const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');

const outDir = path.resolve(process.argv[2] || '.');
const password = process.argv[3] || 'test1234';
const sampleText = 'This file was encrypted for authorized password-recovery testing.\n';

fs.mkdirSync(outDir, { recursive: true });

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024, ...opts }, (err, stdout, stderr) => {
      resolve({ ok: !err, stdout, stderr, err });
    });
  });
}

async function toolAvailable(cmd) {
  const r = await run('which', [cmd]);
  return r.ok;
}

async function generateGpg() {
  if (!(await toolAvailable('gpg'))) return { skipped: 'gpg not installed' };
  const inputPath = path.join(outDir, '.gpg-src.txt');
  const outPath = path.join(outDir, 'sample.gpg');
  fs.writeFileSync(inputPath, sampleText);
  const r = await run('gpg', ['--batch', '--yes', '--passphrase', password, '--cipher-algo', 'AES256',
    '--symmetric', '-o', outPath, inputPath]);
  fs.unlinkSync(inputPath);
  if (!r.ok) return { error: r.stderr || String(r.err) };
  return { path: outPath };
}

async function generate7z() {
  if (!(await toolAvailable('7z'))) return { skipped: '7z not installed' };
  const inputPath = path.join(outDir, '.7z-src.txt');
  const outPath = path.join(outDir, 'sample.7z');
  fs.writeFileSync(inputPath, sampleText);
  const r = await run('7z', ['a', `-p${password}`, '-mhe=on', outPath, inputPath]);
  fs.unlinkSync(inputPath);
  if (!r.ok) return { error: r.stderr || r.stdout };
  return { path: outPath };
}

async function generateRar() {
  if (!(await toolAvailable('rar'))) return { skipped: 'rar not installed (proprietary; package "rar" in the multiverse/universe repo)' };
  const inputPath = path.join(outDir, '.rar-src.txt');
  const outPath = path.join(outDir, 'sample.rar');
  fs.writeFileSync(inputPath, sampleText);
  if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
  const r = await run('rar', ['a', `-p${password}`, '-hp', outPath, inputPath]);
  fs.unlinkSync(inputPath);
  if (!r.ok) return { error: r.stderr || r.stdout };
  return { path: outPath };
}

async function generateOffice() {
  if (!(await toolAvailable('soffice'))) return { skipped: 'soffice (LibreOffice) not installed' };
  const script = path.join(__dirname, 'office_encrypt.py');
  const r = await run('python3', [script, outDir, password], { timeout: 60000 });
  if (!r.ok) return { error: r.stderr || r.stdout };
  return { paths: [path.join(outDir, 'sample-office.docx'), path.join(outDir, 'sample-office.xlsx'), path.join(outDir, 'sample-office.pptx')] };
}

(async () => {
  console.log(`Generating encrypted samples in ${outDir} with password "${password}"...\n`);
  const results = {
    'GPG (AES-256 symmetric)': await generateGpg(),
    '7z (AES-256, encrypted header)': await generate7z(),
    'RAR (AES-256, encrypted header)': await generateRar(),
    'Office Open XML (.docx/.xlsx/.pptx, Agile encryption)': await generateOffice(),
  };

  for (const [label, result] of Object.entries(results)) {
    if (result.path) console.log(`[OK]      ${label} -> ${result.path}`);
    else if (result.paths) console.log(`[OK]      ${label} -> ${result.paths.join(', ')}`);
    else if (result.skipped) console.log(`[SKIPPED] ${label}: ${result.skipped}`);
    else console.log(`[FAILED]  ${label}: ${result.error}`);
  }
  console.log(`\nKnown password for every generated file: "${password}"`);
  console.log('Load these into the browser app\'s identification panel to see detection in action,');
  console.log('or run inspect.js against the RAR/7z/GPG ones for a detection-only listing.');
})();
