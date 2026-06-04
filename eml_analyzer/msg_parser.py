"""Convert Outlook .msg files to RFC 5322 bytes for EmlParser."""

from __future__ import annotations

import email.utils
import io
from email import message_from_string
from email import encoders as email_encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def msg_to_eml_bytes(path: str) -> bytes:
    """Parse a .msg file at *path* and return RFC 5322 email bytes."""
    _require_extract_msg()
    import extract_msg

    with extract_msg.Message(path) as msg:
        return _convert(msg)


def msg_bytes_to_eml_bytes(data: bytes) -> bytes:
    """Parse raw .msg *data* bytes and return RFC 5322 email bytes."""
    _require_extract_msg()
    import extract_msg

    with extract_msg.Message(io.BytesIO(data)) as msg:
        return _convert(msg)


def _require_extract_msg() -> None:
    try:
        import extract_msg  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "extract-msg is required for .msg support. Install it with: pip install extract-msg"
        ) from exc


def _convert(msg: object) -> bytes:
    """Convert an extract_msg Message object to RFC 5322 bytes."""
    html_body = _get_html_body(msg)
    text_body = _safe_str(getattr(msg, "body", None))
    attachments = list(getattr(msg, "attachments", None) or [])

    regular_atts = [a for a in attachments if not _is_nested_msg(a)]
    nested_msg_atts = [a for a in attachments if _is_nested_msg(a)]

    has_html = bool(html_body)
    has_text = bool(text_body)
    has_atts = bool(regular_atts or nested_msg_atts)

    if has_atts:
        outer: MIMEBase = MIMEMultipart("mixed")
        body_part = _build_body_part(has_text, text_body, has_html, html_body)
        if body_part is not None:
            outer.attach(body_part)
        for att in regular_atts:
            outer.attach(_make_attachment_part(att))
        for nested_att in nested_msg_atts:
            outer.attach(_make_nested_msg_part(nested_att))
    else:
        body_part = _build_body_part(has_text, text_body, has_html, html_body)
        outer = body_part if body_part is not None else MIMEMultipart("mixed")

    _apply_headers(outer, msg)
    return outer.as_bytes()


def _build_body_part(
    has_text: bool,
    text_body: str | None,
    has_html: bool,
    html_body: str | None,
) -> MIMEBase | None:
    if has_text and has_html:
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(text_body or "", "plain", "utf-8"))
        alt.attach(MIMEText(html_body or "", "html", "utf-8"))
        return alt
    if has_html:
        return MIMEText(html_body or "", "html", "utf-8")
    if has_text:
        return MIMEText(text_body or "", "plain", "utf-8")
    return None


_SKIP_HEADERS = frozenset(
    {"content-type", "content-transfer-encoding", "mime-version", "content-disposition"}
)


def _apply_headers(em: MIMEBase, msg: object) -> None:
    """Populate *em* headers from transport headers or MAPI properties."""
    transport_headers: str | None = _get_transport_headers(msg)

    if isinstance(transport_headers, str) and transport_headers.strip():
        parsed = message_from_string(transport_headers.strip() + "\r\n\r\n")
        seen: set[str] = set()
        for key in parsed.keys():
            lower = key.lower()
            if lower in _SKIP_HEADERS:
                continue
            if lower in seen:
                continue
            seen.add(lower)
            val = parsed.get(key)
            if val:
                try:
                    em[key] = val
                except Exception:
                    pass
    else:
        _set_header(em, "Subject", _safe_str(getattr(msg, "subject", None)))
        _set_header(em, "From", _safe_str(getattr(msg, "sender", None)))
        _set_header(em, "To", _safe_str(getattr(msg, "to", None)))
        cc = _safe_str(getattr(msg, "cc", None))
        if cc:
            _set_header(em, "Cc", cc)
        date = getattr(msg, "date", None)
        if date is not None:
            try:
                import datetime

                if isinstance(date, datetime.datetime):
                    _set_header(em, "Date", email.utils.format_datetime(date))
            except Exception:
                pass
        _set_header(em, "Message-ID", _safe_str(getattr(msg, "messageId", None)))


def _set_header(em: MIMEBase, key: str, value: str | None) -> None:
    if value and value.strip():
        try:
            em[key] = value.strip()
        except Exception:
            pass


def _make_attachment_part(att: object) -> MIMEBase:
    import mimetypes

    data: bytes = getattr(att, "data", None) or b""
    fname: str = (
        getattr(att, "longFilename", None)
        or getattr(att, "shortFilename", None)
        or "attachment.bin"
    )
    ctype: str = (
        getattr(att, "mimetype", None)
        or mimetypes.guess_type(fname)[0]
        or "application/octet-stream"
    )
    if "/" in ctype:
        maintype, subtype = ctype.split("/", 1)
    else:
        maintype, subtype = "application", "octet-stream"

    part = MIMEBase(maintype, subtype)
    part.set_payload(data)
    email_encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=fname)
    return part


def _make_nested_msg_part(att: object) -> MIMEBase:
    """Convert a nested .msg attachment to a ``message/rfc822`` MIME part."""
    nested_msg_obj = _get_nested_msg_object(att)
    try:
        if nested_msg_obj is not None:
            nested_bytes = _convert(nested_msg_obj)
        else:
            raw = getattr(att, "data", None) or b""
            nested_bytes = msg_bytes_to_eml_bytes(raw) if raw else b""
    except Exception:
        nested_bytes = b""

    fname: str = (
        getattr(att, "longFilename", None)
        or getattr(att, "shortFilename", None)
        or "nested.msg"
    )
    part = MIMEBase("message", "rfc822")
    part.set_payload(nested_bytes)
    part.add_header("Content-Disposition", "attachment", filename=fname)
    return part


def _is_nested_msg(att: object) -> bool:
    """Return True if *att* represents an embedded MSG message."""
    is_msg = getattr(att, "isMsg", None)
    if is_msg is not None:
        return bool(is_msg)
    # Fallback: check if data is a Message-like object (not plain bytes)
    data = getattr(att, "data", None)
    return data is not None and not isinstance(data, (bytes, bytearray)) and hasattr(data, "body")


def _get_nested_msg_object(att: object) -> object | None:
    """Return the inner Message object from a nested MSG attachment, if any."""
    data = getattr(att, "data", None)
    if data is not None and not isinstance(data, (bytes, bytearray)) and hasattr(data, "body"):
        return data
    return None


def _get_html_body(msg: object) -> str | None:
    val = getattr(msg, "htmlBody", None)
    if val is None:
        return None
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val) if not isinstance(val, str) else val


def _get_transport_headers(msg: object) -> str | None:
    """Return the transport headers string from an extract_msg Message."""
    # extract-msg >= 0.48 exposes headerText as a raw string
    raw = getattr(msg, "headerText", None)
    if isinstance(raw, str) and raw.strip():
        return raw
    # Older versions / fallback: msg.header may be str or email.message.Message
    h = None
    try:
        h = getattr(msg, "header", None)
    except Exception:
        pass
    if h is None:
        return None
    if isinstance(h, str):
        return h if h.strip() else None
    # email.message.Message object — convert to string
    try:
        s = str(h)
        return s if s.strip() else None
    except Exception:
        return None


def _safe_str(val: object) -> str | None:
    if val is None:
        return None
    return str(val) if not isinstance(val, str) else val
