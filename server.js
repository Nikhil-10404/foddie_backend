// server.js (only the changed parts)
const { users } = require("./appwrite");
const { sendEmail } = require("./mailer");
const {
  putOTP, getOTP, delOTP, canResend, markResent,
  OTP_TTL_MS, RESEND_COOLDOWN_MS, MAX_RESENDS
} = require("./otpStore");

// Create or resend OTP
app.post("/auth/otp/start", async (req, res) => {
  try {
    const body = z.object({ userId: z.string().min(1) }).parse(req.body);
    const u = await users.get(body.userId);
    const email = (u.email || "").trim();
    if (!email) return res.json({ ok: true });

    const existing = getOTP(body.userId);
    let entry = existing;

    if (existing) {
      // Resend flow with cooldown & max resends
      const gate = canResend(body.userId);
      if (!gate.ok) {
        if (gate.reason === "cooldown") {
          return res.status(429).json({
            ok: false,
            error: "Please wait before requesting another code.",
            retryInMs: gate.retryInMs
          });
        }
        if (gate.reason === "limit") {
          return res.status(429).json({
            ok: false,
            error: "Too many resends. Please start over later."
          });
        }
      }
      // Reuse the same code window (don’t change code), just re-send email
      await sendEmail(email, "Your password reset code",
        `Your verification code is valid for 10 minutes. If you requested this, use the same code from your email.`
      );
      markResent(body.userId);
    } else {
      // New OTP issuance
      const code = String(Math.floor(100000 + Math.random() * 900000));
      entry = await putOTP(body.userId, email, code);

      // For local dev only:
      if (process.env.NODE_ENV !== "production") {
        console.log(`DEV OTP for ${email}: ${code}`);
      }

      await sendEmail(
        email,
        "Your password reset code",
        `Your verification code is ${code}. It expires in 10 minutes.`
      );
    }

    // Tell client how long remains
    const expiresInMs = Math.max(0, entry.expiresAt - Date.now());
    return res.json({
      ok: true,
      expiresInMs,
      ttlMs: OTP_TTL_MS,
      resendCooldownMs: RESEND_COOLDOWN_MS,
      maxResends: MAX_RESENDS,
    });
  } catch (e) {
    console.error("otp/start error", e);
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Verify
app.post("/auth/otp/verify", async (req, res) => {
  try {
    const body = z.object({
      userId: z.string().min(1),
      otp: z.string().length(6),
      newPassword: z.string().min(8),
    }).parse(req.body);

    const entry = getOTP(body.userId);
    if (!entry) {
      return res.status(400).json({ ok: false, error: "expired" }); // specific keyword
    }

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
