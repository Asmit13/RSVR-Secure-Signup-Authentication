import nodemailer from 'nodemailer';

let mailer;
function getMailer() {
  if (!process.env.SMTP_HOST) return null;
  if (!mailer) {
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    });
  }
  return mailer;
}

export async function deliverOtp({ identifier, type, code, purpose }) {
  const subject = purpose === 'signup' ? 'Verify your RSVR account' : 'Your RSVR sign-in code';
  const expiresMinutes = 10;

  if (type === 'email' && process.env.SMTP_HOST) {
    await getMailer().sendMail({
      from: process.env.EMAIL_FROM || 'RSVR Secure Access <no-reply@example.com>',
      to: identifier,
      subject,
      text: `Your RSVR verification code is ${code}. It expires in ${expiresMinutes} minutes. Do not share this code with anyone.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;color:#172033"><p style="font-size:12px;letter-spacing:2px;color:#64748b">RSVR SECURE ACCESS</p><h2>${subject}</h2><p>Use this one-time code to continue. It expires in ${expiresMinutes} minutes.</p><div style="font-size:32px;letter-spacing:9px;font-weight:700;background:#f1f5f9;border-radius:12px;padding:18px;text-align:center">${code}</div><p style="font-size:13px;color:#64748b">Never share this code. RSVR will never ask you to read it out over a call.</p></div>`,
    });
    return;
  }

  if (type === 'phone' && process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER) {
    const account = process.env.TWILIO_ACCOUNT_SID;
    const credentials = Buffer.from(`${account}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
    const form = new URLSearchParams({
      To: identifier,
      From: process.env.TWILIO_FROM_NUMBER,
      Body: `Your RSVR verification code is ${code}. It expires in ${expiresMinutes} minutes. Do not share it.`,
    });
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${account}/Messages.json`, {
      method: 'POST',
      headers: { Authorization: `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    if (!response.ok) throw new Error(`SMS provider rejected the request (${response.status}).`);
    return;
  }

  if (process.env.NODE_ENV !== 'production' && process.env.DEV_OTP === 'true') {
    console.info(`[LOCAL DEVELOPMENT ONLY] ${purpose} OTP for ${identifier}: ${code}`);
    return;
  }

  throw new Error(`No ${type === 'email' ? 'SMTP' : 'SMS'} delivery provider is configured.`);
}
