// otpStore.js
const bcrypt = require("bcryptjs");

const store = new Map(); // userId -> entry

// TTLs & cooldowns (tweak to taste)
const OTP_TTL_MS = 10 * 60_000;    // 10 minutes validity
const RESEND_COOLDOWN_MS = 30_000; // 30s between sends
const MAX_RESENDS = 5;             // per OTP window

async function putOTP(userId, email, code) {
  const codeHash = await bcrypt.hash(code, 10);
  const now = Date.now();
  const entry = {
    email,
    codeHash,
    expiresAt: now + OTP_TTL_MS,
    attempts: 0,
    lastSentAt: now,
    resendCount: 0,
  };
  store.set(userId, entry);
  return entry;
}

function getOTP(userId) {
  const e = store.get(userId);
  if (!e) return null;
  if (Date.now() > e.expiresAt) { store.delete(userId); return null; }
  return e;
}

function delOTP(userId) { store.delete(userId); }

function canResend(userId) {
  const e = store.get(userId);
  if (!e) return { ok: true }; // treat as ok; caller will create new one
  const now = Date.now();

  if (now - e.lastSentAt < RESEND_COOLDOWN_MS) {
    return { ok: false, reason: "cooldown", retryInMs: RESEND_COOLDOWN_MS - (now - e.lastSentAt) };
  }
  if (e.resendCount >= MAX_RESENDS) {
    return { ok: false, reason: "limit" };
  }
  return { ok: true };
}

function markResent(userId) {
  const e = store.get(userId);
  if (!e) return;
  e.resendCount += 1;
  e.lastSentAt = Date.now();
}

module.exports = {
  putOTP, getOTP, delOTP,
  canResend, markResent,
  // export constants so UI can mirror timers if you want
  OTP_TTL_MS, RESEND_COOLDOWN_MS, MAX_RESENDS
};
