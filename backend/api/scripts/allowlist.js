#!/usr/bin/env node
// Manage TAPSEAL allowlists on the server. Run as the tapseal user with the API's environment loaded:
//   sudo -u tapseal bash -c 'set -a; . /etc/tapseal.env; node /opt/tapseal/api/scripts/allowlist.js <command>'
//
//   new-key                          print a fresh signing key (put it in /etc/tapseal.env as WL_SIGNING_KEY)
//   key                              show the public key to use in the token's allowlist settings
//   add <TICK> <file.csv> [--expiry H] [--max N] [--replace]
//                                    CSV rows: address[,max tokens]. --max is the default allowance in tokens.
//                                    --expiry defaults to the end of the token's allowlist phase.
//   remove <TICK> <address>...       take wallets off the list (passes already used on chain stay used)
//   list <TICK>                      show wallets, allowances and what each has used
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: process.env.TAPSEAL_ENV || path.join(__dirname, '..', '.env') });
const ts = require('../src/tapseal');
const dbm = require('../src/db');
const { store, signer } = require('../src/allowlist');

const net = process.env.NETWORK || 'mainnet';
const file = process.env.ALLOWLIST_FILE || '/var/lib/tapseal/allowlist.json';
const die = (m) => { console.error('error: ' + m); process.exit(1); };
const [cmd, ...rest] = process.argv.slice(2);
const flag = (name) => { const i = rest.indexOf(name); if (i < 0) return null; const v = rest[i + 1]; rest.splice(i, 2); return v; };
const bool = (name) => { const i = rest.indexOf(name); if (i < 0) return false; rest.splice(i, 1); return true; };
const toAtoms = (v, dec) => { const [i, f = ''] = String(v).trim().split('.'); if (!/^\d+$/.test(i || '0') || !/^\d*$/.test(f) || f.length > dec) throw new Error(`bad amount ${v}`); return BigInt(i || '0') * 10n ** BigInt(dec) + BigInt((f + '0'.repeat(dec)).slice(0, dec) || '0'); };
const fromAtoms = (a, dec) => { const s = BigInt(a).toString().padStart(dec + 1, '0'); return dec ? `${s.slice(0, -dec)}.${s.slice(-dec)}`.replace(/\.?0+$/, '') : s; };

function token(tick) {
  const db = dbm.open(process.env.TAPSEAL_DB || '/var/lib/tapseal/tapseal.sqlite');
  const t = db.token(String(tick || '').toUpperCase());
  if (!t) die(`unknown token ${tick}`);
  return { db, t };
}

if (cmd === 'new-key') {
  const k = crypto.randomBytes(32).toString('hex');
  console.log(`WL_SIGNING_KEY=${k}\npublic key: ${ts.xonlyOf(k)}\nStore the line above in /etc/tapseal.env (mode 600) and restart tapseal-api.`);
} else if (cmd === 'key') {
  const s = signer(process.env.WL_SIGNING_KEY);
  if (!s) die('WL_SIGNING_KEY is not set');
  console.log(s.pub);
} else if (cmd === 'add') {
  const [tick, csv] = rest; const expiryArg = flag('--expiry'), maxArg = flag('--max'), replace = bool('--replace');
  if (!tick || !csv) die('usage: add <TICK> <file.csv> [--expiry H] [--max N] [--replace]');
  const { t } = token(tick);
  const expiry = Number(expiryArg || (t.wl && t.wl.end) || 0);
  if (!expiry) die('set --expiry, or post the token\'s allowlist settings first so its end height is known');
  const rows = [], errors = [];
  fs.readFileSync(csv, 'utf8').split(/\r?\n/).forEach((line, n) => {
    const [address, max] = line.split(',').map((x) => (x || '').trim());
    if (!address || address.startsWith('#') || /^address$/i.test(address)) return;
    try {
      const owner = ts.ownerOfAddress(address, net).toString('hex');
      const amount = max || maxArg;
      if (!amount) throw new Error('no allowance: add a second column or --max');
      rows.push({ owner, address, max: toAtoms(amount, t.dec), expiry });
    } catch (e) { errors.push(`line ${n + 1}: ${address}: ${e.message}`); }
  });
  if (errors.length) die(`${errors.length} bad row(s), nothing saved:\n  ` + errors.join('\n  '));
  const total = store(file).put(t.tick, rows, replace);
  console.log(`${rows.length} wallet(s) saved for ${t.tick}, ${total} on the list, passes expire after block ${expiry}. File: ${file}`);
} else if (cmd === 'remove') {
  const [tick, ...addrs] = rest;
  const { t } = token(tick);
  const n = store(file).remove(t.tick, addrs.map((a) => ts.ownerOfAddress(a, net).toString('hex')));
  console.log(`${n} wallet(s) removed from ${t.tick}.`);
} else if (cmd === 'list') {
  const { db, t } = token(rest[0]);
  const l = store(file).list(t.tick);
  const rowsOut = Object.entries(l.entries).map(([owner, e]) => `${e.address}  allowance ${fromAtoms(e.max, t.dec)}  used ${fromAtoms(db.usage(t.tick, 'wl', owner), t.dec)}  expires ${e.expiry}`);
  console.log(`${t.tick}: ${rowsOut.length} wallet(s)` + (t.wl ? `, phase ends ${t.wl.end}, reserve ${fromAtoms(t.wl.reserve, t.dec)}, minted ${fromAtoms(t.wl_minted, t.dec)}` : ', no allowlist settings on chain yet'));
  for (const r of rowsOut) console.log('  ' + r);
} else {
  console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(1, 16).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
}
