// otpStore.js
const { Redis } = require("@upstash/redis");
const bcrypt = require("bcryptjs");

const OTP_TTL_MS = Number(process.env.OTP_TTL_MS || 10 * 60_000);
const RESEND_COOLDOWN_MS = Number(process.env.RESEND_COOLDOWN_MS || 30_000);
const MAX_RESENDS = Number(process.env.MAX_RESENDS || 5);

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const keyFor = (userId) => `otp:${userId}`;

function safeParse(json) {
  if (json == null) return null;
  if (typeof json !== "string") {
    // If someone mistakenly wrote a raw object with a different client,
    // bail out and let caller treat as missing/expired.
    return null;
  }
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Save entry back to Redis with the remaining TTL.
 */
async function saveOTPEntry(userId, entry) {
  const remaining = Math.max(0, (entry.expiresAt || 0) - Date.now());
  if (remaining <= 0) {
    await redis.del(keyFor(userId));
    return;
  }
  await redis.set(keyFor(userId), JSON.stringify(entry), { px: remaining });
}

/**
 * Create/store a new OTP entry for user.
 */
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

/**
 * Read the OTP entry; return null if expired or malformed.
 * Auto-heals bad legacy values by deleting them.
 */
async function getOTP(userId) {
  const raw = await redis.get(keyFor(userId));
  const entry = safeParse(raw);
  if (!entry) {
    // Delete bad/legacy value like "[object Object]" so a new code fixes it.
    if (raw) await redis.del(keyFor(userId));
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

/**
 * Enforce resend cooldown and max resend limit.
 */
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
