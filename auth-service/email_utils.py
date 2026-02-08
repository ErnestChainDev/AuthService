import os
import smtplib
from email.mime.text import MIMEText

def send_reset_link_email(to_email: str, reset_link: str) -> None:
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("SMTP_FROM", user)

    if not host or not user or not password or not from_email:
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_FROM.")

    subject = "Reset your password"
    body = (
        "You requested a password reset.\n\n"
        f"Click this link to set a new password:\n{reset_link}\n\n"
        "If you didn't request this, you can ignore this email."
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(from_email, [to_email], msg.as_string())