from PIL import Image
import logging
import io

def convert_image_to_bytes(image: Image.Image, format: str = "PNG") -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format=format)
    image_bytes = buffer.getvalue()
    buffer.close()
    logging.debug("Converted image to %d bytes in memory", len(image_bytes))
    return image_bytes