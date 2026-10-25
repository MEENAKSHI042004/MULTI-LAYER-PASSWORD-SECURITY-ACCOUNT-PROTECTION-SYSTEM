"""Local QR code rendering for TOTP enrolment.

The provisioning URI contains the user's TOTP secret, so it must never be
sent to a third-party QR service. The QR code is drawn here, on the server,
and returned as inline SVG markup.
"""

import segno


def provisioning_qr_svg(uri: str) -> str:
    qr = segno.make(uri, error="m")
    return qr.svg_inline(scale=5, border=2, dark="#000000", light="#ffffff")