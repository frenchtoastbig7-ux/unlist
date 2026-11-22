"""Outbound email from a mailbox created for opt-outs. Settings come from the environment."""

from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from unlist import __version__


class ConfigError(ValueError):
    """A mailbox setting in the environment that cannot be used as written."""


def env_port(name: str, default: int) -> int:
    """A TCP port from the environment: the default when unset or empty, else 1-65535."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ConfigError(f"{name} must be a port number from 1 to 65535, not {raw!r}")
    return port


@dataclass
class SmtpSettings:
    host: str
    port: int
    user: str
    password: str
    from_address: str
    from_name: str = ""

    @classmethod
    def from_env(cls) -> SmtpSettings | None:
        host = os.environ.get("UNLIST_SMTP_HOST")
        user = os.environ.get("UNLIST_SMTP_USER")
        password = os.environ.get("UNLIST_SMTP_PASSWORD")
        if not (host and user and password):
            return None
        return cls(
            host=host,
            port=env_port("UNLIST_SMTP_PORT", 587),
            user=user,
            password=password,
            from_address=os.environ.get("UNLIST_FROM_ADDRESS") or user,
            from_name=os.environ.get("UNLIST_FROM_NAME") or "",
        )


class Mailer:
    def __init__(self, settings: SmtpSettings) -> None:
        self.s = settings

    def build(self, to: str, subject: str, body: str, tag: str) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = (
            f"{self.s.from_name} <{self.s.from_address}>"
            if self.s.from_name
            else self.s.from_address
        )
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain=self.s.from_address.split("@")[-1])
        msg["X-Unlist-Tag"] = tag
        msg["User-Agent"] = f"unlist/{__version__}"
        msg.set_content(body)
        return msg

    def send(self, to: str, subject: str, body: str, tag: str) -> str:
        msg = self.build(to, subject, body, tag)
        ctx = ssl.create_default_context()
        if self.s.port == 465:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(self.s.host, self.s.port, context=ctx, timeout=30)
        else:
            smtp = smtplib.SMTP(self.s.host, self.s.port, timeout=30)
        try:
            if self.s.port != 465:
                smtp.ehlo()
                smtp.starttls(context=ctx)
                smtp.ehlo()
            smtp.login(self.s.user, self.s.password)
            smtp.send_message(msg)
        except BaseException:
            smtp.close()
            raise
        # The server has accepted the message. A failed QUIT must not look like a failed
        # send, or the request would stay approved and go out a second time.
        try:
            smtp.quit()
        except (smtplib.SMTPException, OSError):
            smtp.close()
        return msg["Message-ID"]


@dataclass
class FakeMailer:
    """For tests and dry runs: records what would have been sent."""

    sent: list[dict] = field(default_factory=list)
    fail_for: set[str] = field(default_factory=set)

    def send(self, to: str, subject: str, body: str, tag: str) -> str:
        if to in self.fail_for:
            raise RuntimeError(f"refused by fake server for {to}")
        self.sent.append({"to": to, "subject": subject, "body": body, "tag": tag})
        return f"<fake-{len(self.sent)}@unlist.local>"
