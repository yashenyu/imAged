import sys
import os
from pathlib import Path

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QUrl
from PySide6.QtQml import QQmlApplicationEngine

from ..core.api import PythonAPI

def main():
    app = QApplication(sys.argv)
    engine = QQmlApplicationEngine()
    api = PythonAPI()

    # Set up the Python API
    engine.rootContext().setContextProperty("python", api)

    # Try to find the QML file in the installed package first
    qml_paths = [
        # Installed package path
        Path(sys.prefix) / "share" / "imaged" / "qml" / "MainView.qml",
        # Development path
        Path(__file__).resolve().parent.parent.parent.parent / "resources" / "qml" / "MainView.qml",
    ]
    
    print("Searching for MainView.qml in:")
    for path in qml_paths:
        print(f"  {path} (exists: {path.exists()})")
    
    qml_file = None
    for path in qml_paths:
        if path.exists():
            qml_file = path
            print(f"Found QML file at: {qml_file}")
            break
    
    if not qml_file:
        print("Error: Could not find MainView.qml")
        sys.exit(-1)
        
    engine.load(QUrl.fromLocalFile(str(qml_file)))

    if not engine.rootObjects():
        print("Error: Failed to load QML file")
        sys.exit(-1)

    sys.exit(app.exec())

if __name__ == "__main__":
    main() 