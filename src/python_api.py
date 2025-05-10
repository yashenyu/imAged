import sys
import os
import shutil
import logging
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import QApplication, QFileDialog
from PySide6.QtCore    import QObject, Slot, Property, Signal, QUrl
from PySide6.QtQml     import QQmlApplicationEngine

from converter import convert_to_ttl, open_ttl
from config    import load_config, save_config

class PythonAPI(QObject):
    imageUrlChanged   = Signal()
    statusTextChanged = Signal()
    defaultTtlChanged = Signal()
    ntpServerChanged  = Signal()
    outputDirChanged  = Signal()
    progressChanged   = Signal()
    totalChanged      = Signal()

    def __init__(self):
        super().__init__()
        self._imageUrl   = ""
        self._statusText = ""
        self._load_prefs()
        self._progress   = 0
        self._total      = 0

    def _load_prefs(self):
        cfg = load_config()
        self._defaultTtl = cfg["default_ttl_hours"]
        self._ntpServer  = cfg["ntp_server"]
        self._outputDir  = cfg["output_dir"]

    @Property(str, notify=imageUrlChanged)
    def imageUrl(self): return self._imageUrl

    @Property(str, notify=statusTextChanged)
    def statusText(self): return self._statusText

    @Property(int, notify=defaultTtlChanged)
    def defaultTtlHours(self): return self._defaultTtl

    @Property(str, notify=ntpServerChanged)
    def ntpServer(self): return self._ntpServer

    @Property(str, notify=outputDirChanged)
    def outputDir(self): return self._outputDir

    @Property(int, notify=progressChanged)
    def progress(self): return self._progress

    @Property(int, notify=totalChanged)
    def total(self): return self._total

    @Slot()
    def openImage(self):
        logging.info("Open Image")
        fn, _ = QFileDialog.getOpenFileName(None, "Open Image", "", "Images (*.png *.jpg *.jpeg)")
        if not fn:
            return
        self._imageUrl   = QUrl.fromLocalFile(fn).toString()
        self.imageUrlChanged.emit()
        self._statusText = f"Loaded: {fn}"
        self.statusTextChanged.emit()

    @Slot()
    def openTtl(self):
        logging.info("Open .ttl")
        fn, _ = QFileDialog.getOpenFileName(None, "Open .ttl", "", "ImAged Files (*.ttl)")
        if not fn:
            return
        try:
            png, fallback = open_ttl(fn)
            self._imageUrl = QUrl.fromLocalFile(png).toString()
            self.imageUrlChanged.emit()
            msg = f"Opened: {Path(fn).name}"
            if fallback:
                msg = "Warning: NTP failed; " + msg
            self._statusText = msg
        except Exception as e:
            self._statusText = f"Open failed: {e}"
        self.statusTextChanged.emit()

    @Slot()
    def convertToTtl(self):
        logging.info("Default 1h TTL")
        fn = QUrl(self._imageUrl).toLocalFile()
        if not fn:
            self._statusText = "No image loaded"
            self.statusTextChanged.emit()
            return
        try:
            out = convert_to_ttl(fn)
            self._statusText = f"Converted: {out}"
        except Exception as e:
            self._statusText = f"Convert failed: {e}"
        self.statusTextChanged.emit()

    @Slot(int, int, int, int, int)
    def convertToTtlCustom(self, year, month, day, hour, minute):
        logging.info(f"Custom TTL {year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}")
        fn = QUrl(self._imageUrl).toLocalFile()
        if not fn:
            self._statusText = "No image loaded"
            self.statusTextChanged.emit()
            return
        try:
            from datetime import datetime
            dt = datetime(year, month, day, hour, minute)
            expiry_ts = int(dt.timestamp())
            out = convert_to_ttl(fn, expiry_ts=expiry_ts)
            self._statusText = f"Converted: {out}"
        except Exception as e:
            self._statusText = f"Convert failed: {e}"
        self.statusTextChanged.emit()

    @Slot()
    def saveAsPng(self):
        logging.info("Save as PNG")
        fn = QUrl(self._imageUrl).toLocalFile()
        if not fn:
            self._statusText = "Nothing to save"
            self.statusTextChanged.emit()
            return
        default = Path(fn).stem + "_export.png"
        dest, _ = QFileDialog.getSaveFileName(None, "Save As PNG", default, "PNG Files (*.png)")
        if not dest:
            return
        try:
            shutil.copy(fn, dest)
            self._statusText = f"Saved PNG: {dest}"
        except Exception as e:
            self._statusText = f"Save failed: {e}"
        self.statusTextChanged.emit()

    @Slot(str)
    def batchConvert(self, dirUrl):
        logging.info(f"Batch convert: {dirUrl}")
        folder = QUrl(dirUrl).toLocalFile()
        if not os.path.isdir(folder):
            self._statusText = "Not a valid directory"
            self.statusTextChanged.emit()
            return
        files = sorted(f for f in os.listdir(folder) if f.lower().endswith((".png",".jpg",".jpeg")))
        if not files:
            self._statusText = "No images found"
            self.statusTextChanged.emit()
            return
        self._total = len(files); self.totalChanged.emit()
        self._progress = 0; self.progressChanged.emit()
        for i, fn in enumerate(files, 1):
            src = os.path.join(folder, fn)
            try:
                convert_to_ttl(src)
                self._statusText = f"[{i}/{self._total}] Converted: {fn}"
            except Exception as e:
                self._statusText = f"[{i}/{self._total}] Error: {e}"
            self._progress = i; self.progressChanged.emit(); self.statusTextChanged.emit()
        self._statusText = f"Batch done: {self._total} files"
        self.statusTextChanged.emit()

    @Slot(str, str, str)
    def savePreferences(self, ttlStr, ntpSrv, outDir):
        try:
            ttl = int(ttlStr)
            cfg = {"default_ttl_hours":ttl, "ntp_server":ntpSrv, "output_dir":outDir}
            save_config(cfg)
            self._defaultTtl = ttl; self._ntpServer = ntpSrv; self._outputDir = outDir
            self.defaultTtlChanged.emit(); self.ntpServerChanged.emit(); self.outputDirChanged.emit()
            self._statusText = "Preferences saved"
        except Exception as e:
            self._statusText = f"Prefs failed: {e}"
        self.statusTextChanged.emit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    engine = QQmlApplicationEngine()
    api = PythonAPI()
    engine.rootContext().setContextProperty("pythonApi", api)
    qml = os.path.normpath(os.path.join(Path(__file__).parent, "../qml/main.qml"))
    engine.load(qml)
    if not engine.rootObjects(): sys.exit(-1)
    sys.exit(app.exec())
