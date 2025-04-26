# ImAged Viewer

A Qt-based viewer for ImAged (.ttl) files, which are time-limited image files.

## Features

- View ImAged (.ttl) files
- Automatic expiration checking
- NTP-based time verification
- Modern Material Design UI
- Support for QOI image format

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/im-aged-proj.git
cd im-aged-proj
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the package:
```bash
pip install -e .
```

## Usage

Run the viewer:
```bash
imaged
```

Or run directly with Python:
```bash
python src/imaged/ui/main.py
```

## Development

The project structure is organized as follows:

```
im-aged-proj/
├── src/
│   └── imaged/
│       ├── core/
│       │   ├── __init__.py
│       │   ├── api.py
│       │   └── encoder.py
│       ├── ui/
│       │   ├── __init__.py
│       │   └── main.py
│       └── __init__.py
├── resources/
│   ├── qml/
│   │   └── MainView.qml
│   └── icons/
├── docs/
│   └── FORMAT.md
├── tests/
├── setup.py
└── README.md
```

## License

MIT License 