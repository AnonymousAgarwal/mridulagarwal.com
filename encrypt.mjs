#!/usr/bin/env node
// Encrypts the "interesting links" content for links.html.
//
// Usage:
//   node encrypt.mjs            (reads password + links interactively)
//   node encrypt.mjs <password> (reads links from links.source.html if present)
//
// It prints a JSON blob (salt/iv/ciphertext, all base64) that gets pasted
// into the ENCRYPTED constant in links.html. Only that ciphertext ships to
// the browser, so the links are never visible in page source.

import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

const PBKDF2_ITERATIONS = 250000;

const enc = new TextEncoder();

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

async function main() {
  let password = process.argv[2];
  let plaintext;

  const rl = createInterface({ input: stdin, output: stdout });

  if (!password) {
    password = (await rl.question('Password: ')).trim();
  }

  if (existsSync(new URL('./links.source.html', import.meta.url))) {
    plaintext = readFileSync(new URL('./links.source.html', import.meta.url), 'utf8');
    console.error('\nUsing content from links.source.html');
  } else {
    console.error('\nNo links.source.html found. Paste the inner HTML for the links');
    console.error('section, then type a line containing only END:\n');
    const lines = [];
    while (true) {
      const line = await rl.question('');
      if (line.trim() === 'END') break;
      lines.push(line);
    }
    plaintext = lines.join('\n');
  }
  rl.close();

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
  );

  const blob = {
    v: 1,
    iterations: PBKDF2_ITERATIONS,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(ciphertext),
  };

  console.error('\n--- Paste this as the ENCRYPTED value in links.html ---\n');
  console.log(JSON.stringify(blob, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
