import sys
import os
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# Import the main function
from imaged.ui.main import main

if __name__ == "__main__":
    main() 