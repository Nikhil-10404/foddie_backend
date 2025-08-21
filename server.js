// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const bcrypt = require("bcryptjs");
const { users } = require("./appwrite");   // your Appwrite Admin client helpers
const { sendEmail } = require("./mailer"); // MUST be (to, subject, text)

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
 */
app.post("/auth/otp/start", async (req, res, next) => {
  try {
    const body = z.object({ userId: z.string().min(1, "userId required") }).parse(req.body);

    // Fetch user to get email
    const u = await users.get(body.userId);
    const email = (u?.email || "").trim();
    if (!email) {
      // Silently succeed (avoid enumeration)
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
 * POST /auth/otp/verify
 * body: { userId: string, otp: string(6), newPassword: string(>=8) }
 * Verifies OTP, updates Appwrite password, deletes OTP.
 */
app.post("/auth/otp/verify", async (req, res, next) => {
  try {
    const body = z
      .object({
        userId: z.string().min(1, "userId required"),
        otp: z.string().length(6, "otp must be 6 digits"),
        newPassword: z.string().min(8, "newPassword must be >= 8 chars"),
      })
      .parse(req.body);

    // Read OTP entry (Upstash is async; memory fallback returns value — await works for both)
    const entry = await getOTP(body.userId);
    if (!entry) {
      return res.status(400).json({ ok: false, error: "expired" });
    }

    // Track attempts and persist (if store supports it)
    entry.attempts = (entry.attempts || 0) + 1;
    if (typeof saveOTPEntry === "function") {
      await saveOTPEntry(body.userId, entry);
    }

    if (entry.attempts > 5) {
      await delOTP(body.userId);
      return res.status(429).json({ ok: false, error: "too_many_attempts" });
    }

    const match = await bcrypt.compare(body.otp, entry.codeHash);
    if (!match) {
      return res.status(400).json({ ok: false, error: "invalid_code" });
    }

    // 🔐 Update Appwrite password
    try {
      await users.updatePassword(body.userId, body.newPassword);
    } catch (e) {
      const errMsg =
        (e && e.message) ||
        (e && e.response && e.response.message) ||
        (typeof e === "string" ? e : "appwrite_update_failed");
      return res.status(500).json({ ok: false, error: errMsg });
    }

    await delOTP(body.userId);
    return res.json({ ok: true });
  } catch (err) {
    next(err);
  }
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

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`🟢 OTP backend running on :${PORT}`));
