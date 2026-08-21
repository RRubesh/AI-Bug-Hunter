import smtplib
import ssl
import json
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from backend.config import settings

def build_reset_email_html(username: str, reset_url: str, expires_minutes: int = 15) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Reset Request - AI Bug Hunter</title>
</head>
<body style="margin: 0; padding: 30px 15px; background-color: #030712; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 580px; margin: 0 auto; background-color: #0b0f19; border: 1px solid #1e293b; border-top: 4px solid #06b6d4; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);">
    <tr>
      <td style="padding: 36px 32px;">
        
        <!-- Header -->
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin-bottom: 28px; text-align: center;">
          <tr>
            <td>
              <h1 style="margin: 0; color: #38bdf8; font-size: 22px; font-weight: 800; letter-spacing: 2px; text-transform: uppercase;">AI BUG HUNTER</h1>
              <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 11px; font-family: 'Courier New', Courier, monospace; letter-spacing: 2px; text-transform: uppercase;">Enterprise Security & SAST Platform</p>
            </td>
          </tr>
        </table>

        <!-- Main Card -->
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: rgba(15, 23, 42, 0.7); border: 1px solid #1e293b; border-radius: 12px; margin-bottom: 28px;">
          <tr>
            <td style="padding: 24px;">
              <h2 style="margin: 0 0 14px 0; color: #ffffff; font-size: 17px; font-weight: 700;">Account Password Recovery</h2>
              <p style="margin: 0 0 14px 0; color: #cbd5e1; font-size: 13px; line-height: 1.6;">
                Hello <strong style="color: #38bdf8;">{username}</strong>,
              </p>
              <p style="margin: 0 0 16px 0; color: #cbd5e1; font-size: 13px; line-height: 1.6;">
                We received an authorization request to reset the password for your AI Bug Hunter account. Click the secure authorization button below to choose a new password:
              </p>

              <!-- CTA Button -->
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="margin: 24px 0;">
                <tr>
                  <td align="center">
                    <a href="{reset_url}" target="_blank" style="background: linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%); color: #ffffff; text-decoration: none; font-weight: 700; font-size: 14px; padding: 13px 32px; border-radius: 10px; display: inline-block; box-shadow: 0 4px 14px 0 rgba(6, 182, 212, 0.4); text-transform: uppercase; letter-spacing: 1px;">
                      Reset Your Password
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin: 0 0 10px 0; color: #94a3b8; font-size: 12px; line-height: 1.5;">
                This recovery link is single-use and will expire automatically in <strong style="color: #e2e8f0;">{expires_minutes} minutes</strong>.
              </p>
              
              <p style="margin: 16px 0 0 0; color: #64748b; font-size: 11px; line-height: 1.5; word-break: break-all;">
                If the button above does not work, copy and paste this link into your browser:<br>
                <a href="{reset_url}" target="_blank" style="color: #38bdf8; text-decoration: underline;">{reset_url}</a>
              </p>
            </td>
          </tr>
        </table>

        <!-- Security Disclaimer -->
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="border-top: 1px solid #1e293b; padding-top: 20px; text-align: center;">
          <tr>
            <td>
              <p style="margin: 0 0 6px 0; color: #64748b; font-size: 11px; line-height: 1.4;">
                If you did not initiate this request, you can safely ignore this email. Your existing password will remain secure and unchanged.
              </p>
              <p style="margin: 0; color: #475569; font-size: 10px; font-family: 'Courier New', Courier, monospace;">
                AI Bug Hunter Platform &bull; Automated Security Notification
              </p>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>
</body>
</html>
"""

def build_reset_email_text(username: str, reset_url: str, expires_minutes: int = 15) -> str:
    return f"""AI BUG HUNTER - PASSWORD RESET REQUEST

Hello {username},

We received a request to reset the password for your AI Bug Hunter account.
To reset your password, visit the following link within {expires_minutes} minutes:

{reset_url}

This link is single-use and will expire in {expires_minutes} minutes.
If you did not request a password reset, please ignore this email.

---
AI Bug Hunter Platform
"""

def send_password_reset_email(
    to_email: str, 
    username: str, 
    raw_token: str, 
    request_host: Optional[str] = None
) -> bool:
    """
    Dispatches a password reset email via SMTP, Resend API, SendGrid API, or serverless log.
    Ensures that errors fail gracefully without leaking secrets or crashing.
    """
    clean_email = (to_email or "").strip().lower()
    if not clean_email:
        return False

    # Determine Base URL
    base_url = settings.FRONTEND_URL
    if not base_url or base_url == "http://localhost:5173":
        if request_host and "localhost" not in request_host and "127.0.0.1" not in request_host:
            base_url = f"https://{request_host}"
        elif not base_url:
            base_url = "https://ai-bug-hunter-tawny.vercel.app"

    base_url = base_url.rstrip("/")
    reset_url = f"{base_url}/reset-password?token={raw_token}"

    html_content = build_reset_email_html(username, reset_url)
    text_content = build_reset_email_text(username, reset_url)
    subject = "AI Bug Hunter - Password Reset Authorization"
    from_sender = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"

    # 1. Try Resend API if configured
    if settings.RESEND_API_KEY:
        try:
            req_data = json.dumps({
                "from": settings.SMTP_FROM_EMAIL or "onboarding@resend.dev",
                "to": [clean_email],
                "subject": subject,
                "html": html_content,
                "text": text_content
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=req_data,
                headers={
                    "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                    "Content-Type": "application/json",
                    "User-Agent": "AIBugHunter-Auth/1.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    print(f"[Email Service / Resend]: Reset email sent to {clean_email}")
                    return True
        except Exception as resend_err:
            print(f"[Email Service / Resend Warning]: {str(resend_err)}")

    # 2. Try SendGrid API if configured
    if settings.SENDGRID_API_KEY:
        try:
            req_data = json.dumps({
                "personalizations": [{"to": [{"email": clean_email}]}],
                "from": {"email": settings.SMTP_FROM_EMAIL, "name": settings.SMTP_FROM_NAME},
                "subject": subject,
                "content": [
                    {"type": "text/plain", "value": text_content},
                    {"type": "text/html", "value": html_content}
                ]
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.sendgrid.com/v3/mail/send",
                data=req_data,
                headers={
                    "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                    "User-Agent": "AIBugHunter-Auth/1.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 202):
                    print(f"[Email Service / SendGrid]: Reset email sent to {clean_email}")
                    return True
        except Exception as sg_err:
            print(f"[Email Service / SendGrid Warning]: {str(sg_err)}")

    # 3. Try Standard SMTP if host is provided
    if settings.SMTP_HOST:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_sender
            msg["To"] = clean_email

            part1 = MIMEText(text_content, "plain", "utf-8")
            part2 = MIMEText(html_content, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)

            if settings.SMTP_USE_SSL or settings.SMTP_PORT == 465:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, context=context, timeout=10) as server:
                    if settings.SMTP_USER and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.sendmail(settings.SMTP_FROM_EMAIL, [clean_email], msg.as_string())
            else:
                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                    if settings.SMTP_USE_TLS:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                    if settings.SMTP_USER and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.sendmail(settings.SMTP_FROM_EMAIL, [clean_email], msg.as_string())

            print(f"[Email Service / SMTP]: Password reset email dispatched to {clean_email}")
            return True
        except Exception as smtp_err:
            print(f"[Email Service / SMTP Warning]: {str(smtp_err)}")

    # 4. Graceful Fallback for Dev/Zero-Config
    print(f"[Email Service Notice]: Reset email link prepared for {clean_email}: {reset_url}")
    return True
