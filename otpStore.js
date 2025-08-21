// otpStore.js
const { Redis } = require("@upstash/redis");
const bcrypt = require("bcryptjs");

// Support both *MS and *SECONDS envs
const OTP_TTL_MS =
  process.env.OTP_TTL_MS
    ? Number(process.env.OTP_TTL_MS)
    : process.env.OTP_TTL_SECONDS
      ? Number(process.env.OTP_TTL_SECONDS) * 1000
      : 10 * 60_000; // default 10 min

const RESEND_COOLDOWN_MS =
  process.env.RESEND_COOLDOWN_MS
    ? Number(process.env.RESEND_COOLDOWN_MS)
    : process.env.OTP_RESEND_COOLDOWN
      ? Number(process.env.OTP_RESEND_COOLDOWN) * 1000
      : 30_000; // default 30s

const MAX_RESENDS = Number(process.env.MAX_RESENDS || 5);

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Log which backend we use
if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
  console.warn("[OTP] Upstash env missing. Using in-memory store (NOT SAFE FOR PROD).");
} else {
  console.log("[OTP] Using Upstash Redis:", process.env.UPSTASH_REDIS_REST_URL);
}

const keyFor = (userId) => `otp:${userId}`;

// ✅ Accept object OR string (Upstash may auto-JSON decode)
function coerceEntry(value) {
  if (value == null) return null;
  if (typeof value === "object") return value; // already parsed by Upstash SDK
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch { return null; }
  }
  return null;
}

/** Save entry back with remaining TTL */
async function saveOTPEntry(userId, entry) {
  const remaining = Math.max(0, (entry.expiresAt || 0) - Date.now());
  if (remaining <= 0) {
    await redis.del(keyFor(userId));
    return;
  }
  await redis.set(keyFor(userId), JSON.stringify(entry), { px: remaining });
}

/** Create/store a new OTP entry */
async function putOTP(userId, email, code) {
  const now = Date.now();
  const codeHash = await bcrypt.hash(code, 10);
  const entry = {
    email,
    codeHash,
    expiresAt: now + OTP_TTL_MS,
    attempts: 0,
    lastSentAt: now,
    resendCount: 0,
  };
  await redis.set(keyFor(userId), JSON.stringify(entry), { px: OTP_TTL_MS });
  return entry;
}

/** Read OTP entry; return null if expired/malformed (and clean up bad legacy values) */
async function getOTP(userId) {
  const raw = await redis.get(keyFor(userId));
  const entry = coerceEntry(raw);
  if (!entry) {
    if (raw) await redis.del(keyFor(userId)); // clean malformed legacy values
    return null;
  }
  if (Date.now() > (entry.expiresAt || 0)) {
    await redis.del(keyFor(userId));
    return null;
  }
  return entry;
}

async function delOTP(userId) {
  await redis.del(keyFor(userId));
}

/** Enforce resend cooldown / max resends */
async function canResend(userId) {
  const entry = await getOTP(userId);
  if (!entry) return { ok: true };
  const now = Date.now();
  if (now - (entry.lastSentAt || 0) < RESEND_COOLDOWN_MS) {
    return {
      ok: false,
      reason: "cooldown",
      retryInMs: RESEND_COOLDOWN_MS - (now - entry.lastSentAt),
    };
  }
  if ((entry.resendCount || 0) >= MAX_RESENDS) {
    return { ok: false, reason: "limit" };
  }
  return { ok: true };
}

async function markResent(userId) {
  const entry = await getOTP(userId);
  if (!entry) return;
  entry.resendCount = (entry.resendCount || 0) + 1;
  entry.lastSentAt = Date.now();
  await saveOTPEntry(userId, entry);
}

module.exports = {
  putOTP,
  getOTP,
  delOTP,
  canResend,
  markResent,
  saveOTPEntry,
  OTP_TTL_MS,
  RESEND_COOLDOWN_MS,
  MAX_RESENDS,
};
