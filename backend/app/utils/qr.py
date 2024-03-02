import base64
from io import BytesIO

import qrcode


def generate_qr_code(url: str) -> BytesIO:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = BytesIO()
    img.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    return img_buffer


def generate_qr_code_as_b64(string: str) -> str:
    qr_image = generate_qr_code(string)
    qr_code_base64 = base64.b64encode(qr_image.getvalue()).decode("utf-8")
    return qr_code_base64
