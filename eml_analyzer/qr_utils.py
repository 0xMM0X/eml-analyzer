"""QR code extraction helpers."""

from __future__ import annotations

import io
from typing import Any


_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"}


def extract_qr_codes(
    filename: str | None,
    content_type: str,
    payload: bytes,
    max_pdf_pages: int = 3,
) -> dict[str, Any] | None:
    if not payload:
        return None
    is_pdf = content_type == "application/pdf" or _has_ext(filename, {".pdf"})
    is_image = content_type.startswith("image/") or _has_ext(filename, _IMAGE_EXTS)
    if not is_pdf and not is_image:
        return None

    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception as exc:  # pragma: no cover - optional dependency path
        return {
            "status": "missing",
            "error": f"pyzbar/pillow not available: {exc}",
            "codes": [],
            "tool": "pyzbar",
            "source": "pdf" if is_pdf else "image",
        }

    codes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add_codes(image: "Image.Image") -> None:
        for symbol in zbar_decode(image):
            data_raw = symbol.data
            if isinstance(data_raw, (bytes, bytearray)):
                data_text = data_raw.decode("utf-8", errors="replace")
            else:
                data_text = str(data_raw)
            key = (symbol.type, data_text)
            if key in seen:
                continue
            seen.add(key)
            codes.append({"type": symbol.type, "data": data_text})

    try:
        if is_image:
            image = Image.open(io.BytesIO(payload))
            add_codes(image)
        else:
            try:
                import fitz  # type: ignore
            except Exception as exc:  # pragma: no cover - optional dependency path
                return {
                    "status": "missing",
                    "error": f"pymupdf not available: {exc}",
                    "codes": [],
                    "tool": "pyzbar+pymupdf",
                    "source": "pdf",
                }
            doc = fitz.open(stream=payload, filetype="pdf")
            page_count = min(doc.page_count, max_pdf_pages)
            for idx in range(page_count):
                page = doc.load_page(idx)
                pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                image = Image.open(io.BytesIO(pix.tobytes("png")))
                add_codes(image)
    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc),
            "codes": codes,
            "tool": "pyzbar",
            "source": "pdf" if is_pdf else "image",
        }

    status = "ok"
    return {
        "status": status,
        "codes": codes,
        "tool": "pyzbar" if is_image else "pyzbar+pymupdf",
        "source": "pdf" if is_pdf else "image",
    }


def _has_ext(filename: str | None, exts: set[str]) -> bool:
    if not filename:
        return False
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in exts)
