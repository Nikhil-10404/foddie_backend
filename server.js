// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { z } = require("zod"); // still used in /start (simple)
const bcrypt = require("bcryptjs");
const { users } = require("./appwrite");   // Appwrite Admin client helpers
const { sendEmail } = require("./mailer"); // (to, subject, text)

// ⬇️ Upstash-backed OTP store (root: ./otpStore.js)
const otpStore = require("./otpStore");
const {
  putOTP,
  getOTP,
  delOTP,
  canResend,
  markResent,
  saveOTPEntry, // may be undefined in memory fallback — we guard below
  OTP_TTL_MS = 10 * 60_000,
  RESEND_COOLDOWN_MS = 30_000,
  MAX_RESENDS = 5,
} = otpStore;

// ✅ APP
const app = express();

/* -------------------- CORS (minimal + safe) -------------------- */
// helper to escape strings for RegExp
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Always allow in dev:
//  - Expo Go (exp://...)
//  - Localhost any port (http://localhost:<port>)
const devOrigins = [/^exp:\/\//, /^http:\/\/localhost:\d+$/];

// In production, set WEB_ORIGINS env as comma-separated list, e.g.:
// WEB_ORIGINS=https://myfoodapp.vercel.app,https://www.myfoodapp.com
const prodOriginList = (process.env.WEB_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const prodOrigins = prodOriginList.map((o) => new RegExp("^" + escapeRegex(o) + "$"));

// Final allowlist
const allowlist = [...devOrigins, ...prodOrigins];

const corsOptions = {
  origin(origin, callback) {
    // server-to-server / curl / native apps often have no Origin
    if (!origin) return callback(null, true);
    const allowed = allowlist.some((re) => re.test(origin));
    return allowed ? callback(null, true) : callback(new Error("Not allowed by CORS"));
  },
};

app.use(cors(corsOptions));
/* -------------------------------------------------------------- */

app.use(express.json());
app.use(rateLimit({ windowMs: 10 * 60_000, max: 60 }));

// Health
app.get("/health", (_, res) => res.json({ ok: true }));

/**
 * POST /auth/otp/start
 * body: { userId: string }
 * Sends a 6-digit code to the user's email (looked up via Appwrite).
 * If user not found / no email, returns ok:true silently (avoid enumeration).
 */
app.post("/auth/otp/start", async (req, res, next) => {
  try {
    const body = z.object({ userId: z.string().min(1, "userId required") }).parse(req.body);

    // Try to fetch user; silently succeed if not found or permission error
    let email = "";
    try {
      const u = await users.get(body.userId);
      email = (u?.email || "").trim();
    } catch {
      return res.json({ ok: true });
    }
    if (!email) {
      return res.json({ ok: true });
    }

    // Do we already have an active OTP?
    const existing = await getOTP(body.userId);

    if (existing) {
      const gate = await canResend(body.userId);
      if (!gate.ok) {
        if (gate.reason === "cooldown") {
          return res.status(429).json({
            ok: false,
            error: "Please wait before requesting another code.",
            retryInMs: gate.retryInMs,
          });
        }
        if (gate.reason === "limit") {
          return res.status(429).json({ ok: false, error: "Too many resends. Please try again later." });
        }
      }

      // resend informational email (same code)
      await sendEmail(
        email,
        "Your password reset code",
        `Your verification code is still valid. Check your inbox/spam. It expires 10 minutes from the original send.`
      );
      await markResent(body.userId);

      const expiresInMs = Math.max(0, existing.expiresAt - Date.now());
      return res.json({
        ok: true,
        expiresInMs,
        ttlMs: OTP_TTL_MS,
        resendCooldownMs: RESEND_COOLDOWN_MS,
        maxResends: MAX_RESENDS,
      });
    }

    // No existing OTP — create a new one
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const entry = await putOTP(body.userId, email, code);

    if (process.env.NODE_ENV !== "production") {
      console.log(`DEV OTP for ${email}: ${code}`);
    }

    await sendEmail(
      email,
      "Your password reset code",
      `Your verification code is ${code}. It expires in 10 minutes.`
    );

    const expiresInMs = Math.max(0, entry.expiresAt - Date.now());
    return res.json({
      ok: true,
      expiresInMs,
      ttlMs: OTP_TTL_MS,
      resendCooldownMs: RESEND_COOLDOWN_MS,
      maxResends: MAX_RESENDS,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /auth/otp/verify  (defensive version — no Zod)
 * body: { userId: string, otp: string(6), newPassword: string(>=8) }
 * Verifies OTP, updates Appwrite password, deletes OTP.
 * Always returns clean JSON (no "[object Object]").
 */
app.post("/auth/otp/verify", async (req, res) => {
  // 1) Manual validation (avoid parser-side JSON errors)
  const body = req.body || {};
  const userId = typeof body.userId === "string" ? body.userId.trim() : "";
  const otp = typeof body.otp === "string" ? body.otp.trim() : "";
  const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

  if (!userId) return res.status(400).json({ ok: false, error: "userId_required" });
  if (!/^\d{6}$/.test(otp)) return res.status(400).json({ ok: false, error: "otp_invalid_format" });
  if (newPassword.length < 8) return res.status(400).json({ ok: false, error: "password_too_short" });

  // 2) Read OTP entry
  let entry;
  try {
    entry = await getOTP(userId);
  } catch (e) {
    const msg = (e && e.message) || (typeof e === "string" ? e : "otp_read_failed");
    return res.status(500).json({ ok: false, error: "otp_read_failed", detail: String(msg) });
  }
  if (!entry) return res.status(400).json({ ok: false, error: "expired" });

  // 3) Track attempts (and persist if supported)
  try {
    entry.attempts = (entry.attempts || 0) + 1;
    if (typeof saveOTPEntry === "function") {
      await saveOTPEntry(userId, entry);
    }
    if (entry.attempts > 5) {
      await delOTP(userId);
      return res.status(429).json({ ok: false, error: "too_many_attempts" });
    }
  } catch (e) {
    const msg = (e && e.message) || (typeof e === "string" ? e : "otp_attempts_failed");
    return res.status(500).json({ ok: false, error: "otp_attempts_failed", detail: String(msg) });
  }

  // 4) Compare codes
  let match = false;
  try {
    match = await bcrypt.compare(otp, entry.codeHash);
  } catch (e) {
    const msg = (e && e.message) || (typeof e === "string" ? e : "bcrypt_error");
    return res.status(500).json({ ok: false, error: "bcrypt_error", detail: String(msg) });
  }
  if (!match) return res.status(400).json({ ok: false, error: "invalid_code" });

  // 5) Update Appwrite password
  try {
    await users.updatePassword(userId, newPassword);
  } catch (e) {
    // Appwrite sometimes throws rich objects — normalize to string
    const msg =
      (e && e.message) ||
      (e && e.response && e.response.message) ||
      (typeof e === "string" ? e : JSON.stringify(e));
    return res.status(500).json({ ok: false, error: "appwrite_update_failed", detail: String(msg) });
  }

  // 6) Clean up OTP
  try {
    await delOTP(userId);
  } catch (e) {
    const msg = (e && e.message) || (typeof e === "string" ? e : "otp_delete_failed");
    // Non-fatal cleanup error
    return res.status(200).json({ ok: true, warning: "otp_delete_failed", detail: String(msg) });
  }

  return res.json({ ok: true });
});

// -------- Global JSON error handler (keeps responses valid JSON) --------
app.use((err, req, res, next) => {
  try {
    const status = err?.status || 400;
    const message =
      (typeof err?.message === "string" && err.message) ||
      (typeof err === "string" && err) ||
      err?.error ||
      "request_failed";
    // Log full error for debugging
    console.error("[ERROR]", err);
    res.status(status).json({ ok: false, error: message });
  } catch (e) {
    res.status(500).json({ ok: false, error: "internal_error" });
  }
});

if (process.env.DEBUG_OTP === "1") {
  app.get("/__debug/otp_roundtrip", async (req, res) => {
    try {
      const { Redis } = require("@upstash/redis");
      const r = new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN });
      const key = "otp:__debug";
      await r.set(key, JSON.stringify({ ok: true, t: Date.now() }), { px: 30000 });
      const raw = await r.get(key);
      res.json({ ok: true, raw });
    } catch (e) {
      res.status(500).json({ ok: false, error: String(e?.message || e) });
    }
  });
}

// ---- Admin email update (no client session required) ----
app.post("/auth/account/update-email", async (req, res) => {
  try {
    const body = req.body || {};
    const userId = typeof body.userId === "string" ? body.userId.trim() : "";
    const newEmail = typeof body.newEmail === "string" ? body.newEmail.trim() : "";
    const userDocId = typeof body.userDocId === "string" ? body.userDocId.trim() : ""; // optional

    if (!userId) return res.status(400).json({ ok: false, error: "userId_required" });
    if (!newEmail) return res.status(400).json({ ok: false, error: "email_required" });

    // 1) Update Appwrite Account (admin)
    try {
      await users.updateEmail(userId, newEmail);
    } catch (e) {
      const msg =
        (e && e.message) ||
        (e && e.response && e.response.message) ||
        (typeof e === "string" ? e : "users.updateEmail_failed");
      return res.status(500).json({ ok: false, error: "users.updateEmail_failed", detail: String(msg) });
    }

    // 2) Mirror to Users collection if doc id provided
    if (userDocId) {
      try {
        const { databases } = require("./appwrite");
        const { appwriteConfig } = require("./appwrite");
        await databases.updateDocument(
          appwriteConfig.databaseId,
          appwriteConfig.userCollectionId,
          userDocId,
          { email: newEmail }
        );
      } catch (e) {
        const msg = (e && e.message) || (typeof e === "string" ? e : "mirror_failed");
        // Non-fatal: email changed at source; report warning
        return res.status(200).json({ ok: true, warning: "mirror_failed", detail: String(msg) });
      }
    }

    return res.json({ ok: true });
  } catch (e) {
    const msg = (e && e.message) || (typeof e === "string" ? e : "update_email_failed");
    return res.status(400).json({ ok: false, error: String(msg) });
  }
});


const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`🟢 OTP backend running on :${PORT}`));
