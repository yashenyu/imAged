import sys
import os
import logging
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtQml     import QQmlApplicationEngine
from python_api        import PythonAPI

# ─── Setup Logging ─────────────────────────────────────────────────────────────
root = Path(__file__).parent.parent
log_dir = root / "logs"
log_dir.mkdir(exist_ok=True)
log_file = log_dir / "imaged.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logging.info("=== Starting ImAged Application ===")

# ─── Launch the App ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    engine = QQmlApplicationEngine()

    api = PythonAPI()
    engine.rootContext().setContextProperty("pythonApi", api)

    qml_path = os.path.normpath(
        os.path.join(Path(__file__).parent, os.pardir, "qml", "main.qml")
    )
    engine.load(qml_path)

    if not engine.rootObjects():
        logging.critical("Failed to load QML file: %s", qml_path)
        sys.exit(-1)

    exit_code = app.exec()
    logging.info("=== Exiting ImAged Application with code %d ===", exit_code)
    sys.exit(exit_code)
