// otpStore.js  (root, same folder as server.js)
const { Redis } = require("@upstash/redis");
const bcrypt = require("bcryptjs");

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Keep same config names your server.js expects
const OTP_TTL_MS = Number(process.env.OTP_TTL_MS || 10 * 60_000);        // 10 min
const RESEND_COOLDOWN_MS = Number(process.env.RESEND_COOLDOWN_MS || 30_000);
const MAX_RESENDS = Number(process.env.MAX_RESENDS || 5);

// Keys
const kCode = (userId) => `otp:code:${userId}`;     // hashed code
const kMeta = (userId) => `otp:meta:${userId}`;     // JSON: { email, expiresAt, attempts, lastSentAt, resendCount }
const kCd   = (userId) => `otp:cooldown:${userId}`; // throttle resend

// Create or overwrite OTP entry
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

  // store both with TTL
  await Promise.all([
    redis.set(kCode(userId), codeHash, { px: OTP_TTL_MS }),
    redis.set(kMeta(userId), JSON.stringify(entry), { px: OTP_TTL_MS }),
    redis.set(kCd(userId), "1", { px: RESEND_COOLDOWN_MS }), // start cooldown immediately
  ]);

  return entry;
}

// Read current entry (null if missing/expired). Auto-clean if expired.
async function getOTP(userId) {
  const [metaStr] = await Promise.all([redis.get(kMeta(userId))]);
  if (!metaStr) return null;

  const entry = JSON.parse(metaStr);
  if (Date.now() > entry.expiresAt) {
    await delOTP(userId);
    return null;
  }
  return entry;
}

// Persist an updated entry with the remaining TTL (used for attempts/resends)
async function saveOTPEntry(userId, entry) {
  const ttl = await redis.pttl(kMeta(userId));
  const px = ttl > 0 ? ttl : OTP_TTL_MS;
  await Promise.all([
    redis.set(kMeta(userId), JSON.stringify(entry), { px }),
    // keep code key alive the same remaining time
    redis.pexpire(kCode(userId), px),
  ]);
}

// Delete everything
async function delOTP(userId) {
  await Promise.all([redis.del(kCode(userId)), redis.del(kMeta(userId)), redis.del(kCd(userId))]);
}

// Resend throttle + limits
async function canResend(userId) {
  // cooldown?
  const ttl = await redis.pttl(kCd(userId));
  if (typeof ttl === "number" && ttl > 0) {
    return { ok: false, reason: "cooldown", retryInMs: ttl };
  }

  // check resend count in meta
  const metaStr = await redis.get(kMeta(userId));
  if (!metaStr) return { ok: true }; // no active OTP -> you'll create a new one anyway
  const entry = JSON.parse(metaStr);
  if ((entry.resendCount || 0) >= MAX_RESENDS) return { ok: false, reason: "limit" };
  return { ok: true };
}

async function markResent(userId) {
  const metaStr = await redis.get(kMeta(userId));
  if (!metaStr) return;
  const entry = JSON.parse(metaStr);
  entry.resendCount = (entry.resendCount || 0) + 1;
  entry.lastSentAt = Date.now();
  await saveOTPEntry(userId, entry);
  await redis.set(kCd(userId), "1", { px: RESEND_COOLDOWN_MS }); // re-arm cooldown
}

module.exports = {
  putOTP,
  getOTP,
  delOTP,
  canResend,
  markResent,
  saveOTPEntry,            // <-- you'll call this once in server.js to persist attempts
  OTP_TTL_MS,
  RESEND_COOLDOWN_MS,
  MAX_RESENDS,
};
