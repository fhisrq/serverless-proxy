// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 RethinkDNS and its authors

import * as cfg from "../base/cfg.js";
import * as log from "../base/log.js";
import * as bin from "../base/buf.js";
import {
  hkdfalgkeysz,
  hkdfhmac,
  hmacsign,
  hmacverify,
  hmackey,
  sha256,
  sha512,
} from "../webcrypto/hmac.js";

export const claimPrefix = "pip_";
export const claimDelim = ":";

export const ok = 1;
export const notok = 2;

/**
 *
 * @param {string} seedhex
 * @param {string} ctxhex
 * @returns {Promise<CryptoKey?>}
 */
export async function keygen(seedhex, ctxhex) {
  if (!bin.emptyString(seedhex) && !bin.emptyString(ctxhex)) {
    try {
      const sk = bin.hex2buf(seedhex);
      const sk256 = sk.slice(0, hkdfalgkeysz);
      const info512 = await sha512(bin.hex2buf(ctxhex));
      return await gen(sk256, info512);
    } catch (ignore) {
      log.d("keygen: err", ignore);
    }
  }
  log.d("keygen: invalid seed/ctx");
  return null;
}

/**
 * Scenario 4: privacypass.github.io/protocol
 * @param {CryptoKey} sk
 * @param {string} fullthex
 * @param {string} msghex
 * @param {string} msgmachex
 * @returns {Promise<number>}
 */
export async function verifyClaim(sk, fullthex, msghex, msgmachex, checkExpiry = true) {
  try {
    if (checkExpiry) {
      const y1 = verifyExpiry(fullthex);
      if (!y1) {
        log.d("verifyClaim: expired");
        return notok;
      }
    }
    // shex is the hmac-signature over hashedthex, which is in possession
    // of the client which must have signed msghex with the same key
    const [hashedthex, shex] = await deriveIssue(sk, fullthex);
    if (!hashedthex || !shex) {
      log.d("verifyClaim: cannot derive tok/sig");
      return notok;
    }
    log.d("hashedhtex", hashedthex, "\n shex", shex);
    const y2 = await verifyMessage(shex, msghex, msgmachex);
    if (!y2) {
      log.d("verifyClaim: invalid msg/mac");
      return notok;
    }
    return ok;
  } catch (ignore) {
    log.d("verifyClaim: err", ignore);
  }
  return notok;
}

/**
 * Returns expiryMs and sigthex, hmac(sigkey, expiryMs+hashedthex).
 * Scenario 4: privacypass.github.io/protocol
 * @param {CryptoKey} sigkey
 * @param {string} hashedthex 64-char hex
 * @param {number} expiryMs duration in milliseconds
 * @returns {Promise<[string, string]>} expiryMs and sigthex
 */
export async function issue(sigkey, hashedthex, expiryMs = cfg.minAuthExpiryMs) {
  if (bin.emptyString(hashedthex) || hashedthex.length !== 64) {
    log.d("issue: invalid hashedthex", hashedthex);
    return null;
  }
  if (expiryMs <= 0) {
    log.d("issue: invalid expiryMs", expiryMs);
    return null;
  }
  const when = Date.now() + expiryMs;
  // expiryHex will not exceed 11 chars until 17592186044415 (year 2527)
  // 17592186044415 = 0xfffffffffff
  const expiryHex = when.toString(16);
  hashedthex = expiryHex + hashedthex;
  const hashedtoken = bin.hex2buf(hashedthex);
  const sig = await hmacsign(sigkey, hashedtoken);
  const shex = bin.buf2hex(sig);
  return [expiryHex, shex];
}

/**
 * Returns hashed-token (expiryMs+sha256(user-token)) and a hmac-signature over it.
 * @param {CryptoKey} sigkey
 * @param {string} fullthex
 * @returns {Promise<[string, string]>}
 */
async function deriveIssue(sigkey, fullthex) {
  const expiryHex = fullthex.slice(0, 11);
  const userthex = fullthex.slice(11);
  const usertoken = bin.hex2buf(userthex);
  const userhashedtoken = await sha256(usertoken);
  const hashedthex = expiryHex + bin.buf2hex(userhashedtoken);
  const hashedtoken = bin.hex2buf(hashedthex);
  log.d("userthex", userthex, "\nhashedthex", hashedthex);
  const sig = await hmacsign(sigkey, hashedtoken);
  const signedthex = bin.buf2hex(sig);
  return [hashedthex, signedthex];
}

export async function message(shex, msghex) {
  const sig = bin.hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = bin.hex2buf(msghex);
  const mac = await hmacsign(sigkey, msg);
  const machex = bin.buf2hex(mac);
  return machex;
}

async function verifyMessage(shex, msgstr, msgmachex) {
  const sig = bin.hex2buf(shex);
  const sigkey = await hmackey(sig);
  const msg = bin.hex2buf(msgstr);
  const mac = bin.hex2buf(msgmachex);
  return hmacverify(sigkey, mac, msg);
}

export function verifyExpiry(thex) {
  // expect expiry in hex, at the start of thex; see issue()
  const expiryHex = thex.slice(0, 11);
  const expiryMs = bin.hex2num(expiryHex);
  return expiryMs >= Date.now();
}

export function verifySvcPsk(env, hex) {
  if (env[cfg.wenvPskSvc] == null) return notok;
  return hex === env[cfg.wenvPskSvc] ? ok : notok;
}

// salt for hkdf can be zero: stackoverflow.com/a/64403302
async function gen(secret, info, salt = bin.ZEROBUF) {
  if (bin.emptyBuf(secret) || bin.emptyBuf(info)) {
    throw new Error("auth: empty secret/info");
  }
  log.d("gen: secret", bin.buf2hex(secret));
  // exportable: crypto.subtle.exportKey("raw", key);
  return hkdfhmac(secret, info, salt);
}
