from __future__ import annotations

import base64
import secrets
from email.message import EmailMessage
from typing import Any

import qrcode
from qrcode.image.pil import PilImage

from src.api.core.settings import get_settings


# PUBLIC_INTERFACE
def generate_qr_token() -> str:
    """Generate a random token suitable for embedding in QR codes."""
    # 32 bytes URL-safe => plenty of entropy, store as text in DB
    return secrets.token_urlsafe(32)


# PUBLIC_INTERFACE
def qr_png_data_uri(payload: str) -> str:
    """Return a data: URI (PNG) for a QR encoding of payload.

    This is convenient for frontend display without storing binary blobs server-side.
    """
    img: PilImage = qrcode.make(payload)  # type: ignore[assignment]
    buf = bytearray()
    # PIL image supports save to bytes via memoryview using BytesIO; keep dependencies minimal.
    from io import BytesIO

    bio = BytesIO()
    img.save(bio, format="PNG")
    encoded = base64.b64encode(bio.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# PUBLIC_INTERFACE
def send_email(to_email: str, subject: str, body_text: str) -> None:
    """Send an email via SMTP if configured; otherwise logs to stdout.

    This is intentionally simple for template scaffolding.
    """
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_user or not settings.smtp_password:
        # Safe fallback for dev environments.
        print(
            f"[EMAIL:DEV] To={to_email}\nSubject={subject}\n\n{body_text}\n--- end ---"
        )
        return

    import smtplib

    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body_text)

    if settings.smtp_use_tls:
        server: Any
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
        server.starttls()
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)

    try:
        server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)
    finally:
        server.quit()
