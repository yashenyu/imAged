# Imaged Project

A secure image processing and management system with encryption capabilities.

## Overview

Imaged is a Python-based application that provides secure image processing, conversion, and management features. The project includes a QML-based user interface and implements various security measures for handling sensitive image data.

## Features

- Image conversion and processing
- Secure encryption/decryption of images
- Configuration management
- Logging system
- QML-based user interface
- NTP server synchronization

## Project Structure

```
imaged-proj/
├── src/                    # Source code directory
│   ├── main.py            # Main application entry point
│   ├── python_api.py      # Python API implementation
│   ├── converter.py       # Image conversion utilities
│   ├── crypto.py          # Encryption/decryption functionality
│   └── config.py          # Configuration management
├── qml/                   # QML UI files
├── logs/                  # Application logs
└── config.json           # Application configuration
```

## Requirements

- Python 3.8 or higher
- PyQt5
- Pillow (PIL)
- cryptography
- ntplib
- Other dependencies listed in requirements.txt

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yashenyu/imAged
cd imaged-proj
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The application can be configured through `config.json`:

```json
{
  "default_ttl_hours": 1,
  "ntp_server": "pool.ntp.org",
  "output_dir": ""
}
```

- `default_ttl_hours`: Default time-to-live for processed images
- `ntp_server`: NTP server for time synchronization
- `output_dir`: Directory for output files

## Usage

1. Start the application:
```bash
python src/main.py
```

2. Use the QML interface to:
   - Process images
   - Convert image formats
   - Encrypt/decrypt images
   - Manage configurations

## Logging

Logs are stored in the `logs/` directory. The main log file is `imaged.log`.

## Security

- All sensitive operations use secure encryption
- Time-based security measures with NTP synchronization
- Secure file handling and cleanup

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Specify your license here]

## Support

For support, please [specify contact information or support channels] 
