import qoi
import numpy as np
from PIL import Image
import logging

def encode_image_to_qoi(image_path: str) -> bytes:
    """Convert image to QOI format."""
    img = Image.open(image_path).convert("RGBA")
    arr = np.array(img)
    return qoi.encode(arr)

def decode_qoi_to_image(qoi_data: bytes) -> Image.Image:
    """Convert QOI data back to PIL Image."""
    arr = qoi.decode(qoi_data)
    return Image.fromarray(arr, mode="RGBA")

def save_image_to_temp(image: Image.Image, suffix: str = ".png") -> str:
    """Save image to temporary file and return path."""
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    image.save(tmp.name)
    logging.debug("Saved image to temp file: %s", tmp.name)
    return tmp.name