import sys
import os
from pathlib import Path
from PIL import Image
import numpy as np

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# Import the encoder function
from imaged.core.encoder import make_ttl

def create_test_image(filename="test.png", size=(100, 100)):
    """Create a simple test image with a gradient."""
    # Create a gradient
    x = np.linspace(0, 1, size[0])
    y = np.linspace(0, 1, size[1])
    X, Y = np.meshgrid(x, y)
    
    # Create RGB channels
    R = (X * 255).astype(np.uint8)
    G = (Y * 255).astype(np.uint8)
    B = ((1 - X) * 255).astype(np.uint8)
    
    # Create RGBA array
    img_array = np.stack([R, G, B, np.full_like(R, 255)], axis=-1)
    
    # Convert to PIL Image and save
    img = Image.fromarray(img_array, mode="RGBA")
    img.save(filename, "PNG")
    return filename

if __name__ == "__main__":
    # Create a test image
    test_image = create_test_image()
    print(f"Created test image: {test_image}")
    
    # Create a test.ttl file
    make_ttl(test_image, 3600, "test.ttl")
    print("Created test.ttl successfully") 