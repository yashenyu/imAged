import qoi
import numpy as np
from PIL import Image
import logging
import io

def encode_image_to_qoi(image_path: str) -> bytes:
    """Convert image to QOI format."""
    img = Image.open(image_path).convert("RGBA")
    arr = np.array(img)
    return qoi.encode(arr)

def decode_qoi_to_image(qoi_data: bytes) -> Image.Image:
    """Convert QOI data back to PIL Image."""
    arr = qoi.decode(qoi_data)
    return Image.fromarray(arr, mode="RGBA")

def convert_image_to_bytes(image: Image.Image, format: str = "PNG") -> bytes:
    """Convert PIL Image to bytes in memory."""
    buffer = io.BytesIO()
    image.save(buffer, format=format)
    image_bytes = buffer.getvalue()
    buffer.close()
    logging.debug("Converted image to %d bytes in memory", len(image_bytes))
    return image_bytes