require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const bcrypt = require("bcryptjs");
const { users } = require("./appwrite");
const { sendEmail } = require("./mailer");
const {
  putOTP, getOTP, delOTP, canResend, markResent,
  OTP_TTL_MS = 10 * 60_000, RESEND_COOLDOWN_MS = 30_000, MAX_RESENDS = 5
} = (() => {
  // fallback if your otpStore doesn't export cooldown helpers yet
  try { return require("./otpStore"); }
  catch { 
    // minimal shim
    const store = new Map();
    return {
      putOTP: async (userId, email, code) => {
        const codeHash = await bcrypt.hash(code, 10);
        const now = Date.now();
        const entry = { email, codeHash, expiresAt: now + OTP_TTL_MS, attempts: 0, lastSentAt: now, resendCount: 0 };
        store.set(userId, entry); return entry;
      },
      getOTP: (userId) => {
        const e = store.get(userId); if (!e) return null;
        if (Date.now() > e.expiresAt) { store.delete(userId); return null; }
        return e;
      },
      delOTP: (userId) => store.delete(userId),
      canResend: (userId) => {
        const e = store.get(userId); if (!e) return { ok: true };
        const now = Date.now();
        if (now - e.lastSentAt < RESEND_COOLDOWN_MS) return { ok: false, reason: "cooldown", retryInMs: RESEND_COOLDOWN_MS - (now - e.lastSentAt) };
        if (e.resendCount >= MAX_RESENDS) return { ok: false, reason: "limit" };
        return { ok: true };
      },
      markResent: (userId) => { const e = store.get(userId); if (e) { e.resendCount++; e.lastSentAt = Date.now(); } },
      OTP_TTL_MS, RESEND_COOLDOWN_MS, MAX_RESENDS,
    };
  }
})();

// ✅ CREATE THE APP *before* using it
const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 10 * 60_000, max: 60 }));

app.get("/health", (_, res) => res.json({ ok: true }));

// Start or resend OTP
app.post("/auth/otp/start", async (req, res) => {
  try {
    const body = z.object({ userId: z.string().min(1) }).parse(req.body);
    const u = await users.get(body.userId);
    const email = (u.email || "").trim();
    if (!email) return res.json({ ok: true });

    const existing = getOTP(body.userId);
    let entry = existing;

    if (existing) {
      const gate = canResend(body.userId);
      if (!gate.ok) {
        if (gate.reason === "cooldown") {
          return res.status(429).json({ ok: false, error: "Please wait before requesting another code.", retryInMs: gate.retryInMs });
        }
        if (gate.reason === "limit") {
          return res.status(429).json({ ok: false, error: "Too many resends. Please try again later." });
        }
      }
      await sendEmail(email, "Your password reset code", `Your verification code is still valid. Check your inbox/spam. It expires in 10 minutes from the original send.`);
      markResent(body.userId);
    } else {
      const code = String(Math.floor(100000 + Math.random() * 900000));
      entry = await putOTP(body.userId, email, code);
      if (process.env.NODE_ENV !== "production") console.log(`DEV OTP for ${email}: ${code}`);
      await sendEmail(email, "Your password reset code", `Your verification code is ${code}. It expires in 10 minutes.`);
    }

    const expiresInMs = Math.max(0, entry.expiresAt - Date.now());
    return res.json({ ok: true, expiresInMs, ttlMs: OTP_TTL_MS, resendCooldownMs: RESEND_COOLDOWN_MS, maxResends: MAX_RESENDS });
  } catch (e) {
    console.error("otp/start error", e);
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Verify OTP + set new password
app.post("/auth/otp/verify", async (req, res) => {
  try {
    const body = z.object({
      userId: z.string().min(1),
      otp: z.string().length(6),
      newPassword: z.string().min(8),
    }).parse(req.body);

    const entry = getOTP(body.userId);
    if (!entry) return res.status(400).json({ ok: false, error: "expired" });

    entry.attempts = (entry.attempts || 0) + 1;
    if (entry.attempts > 5) { delOTP(body.userId); return res.status(429).json({ ok: false, error: "too_many_attempts" }); }

    const ok = await bcrypt.compare(body.otp, entry.codeHash);
    if (!ok) return res.status(400).json({ ok: false, error: "invalid_code" });

    await users.updatePassword(body.userId, body.newPassword);
    delOTP(body.userId);
    res.json({ ok: true });
  } catch (e) {
    console.error("otp/verify error", e);
    res.status(400).json({ ok: false, error: e.message });
  }
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`🟢 OTP backend running on :${PORT}`));
