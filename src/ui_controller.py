import sys
import os
import logging
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import QApplication, QFileDialog
from PySide6.QtCore import QObject, Slot, Property, Signal, QUrl

from config import load_config, save_config
from file_manager import TTLFileManager

class UIController(QObject):
    """Handles UI interactions and Qt integration."""
    
    # Signals
    imageUrlChanged = Signal()
    statusTextChanged = Signal()
    defaultTtlChanged = Signal()
    ntpServerChanged = Signal()
    outputDirChanged = Signal()
    progressChanged = Signal()
    totalChanged = Signal()

    def __init__(self):
        super().__init__()
        self._imageUrl = ""
        self._statusText = ""
        self._progress = 0
        self._total = 0
        self._file_manager = TTLFileManager()
        self._load_preferences()

    def _load_preferences(self):
        """Load user preferences from config."""
        cfg = load_config()
        self._defaultTtl = cfg["default_ttl_hours"]
        self._ntpServer = cfg["ntp_server"]
        self._outputDir = cfg["output_dir"]

    # Properties
    @Property(str, notify=imageUrlChanged)
    def imageUrl(self): 
        return self._imageUrl

    @Property(str, notify=statusTextChanged)
    def statusText(self): 
        return self._statusText

    @Property(int, notify=defaultTtlChanged)
    def defaultTtlHours(self): 
        return self._defaultTtl

    @Property(str, notify=ntpServerChanged)
    def ntpServer(self): 
        return self._ntpServer

    @Property(str, notify=outputDirChanged)
    def outputDir(self): 
        return self._outputDir

    @Property(int, notify=progressChanged)
    def progress(self): 
        return self._progress

    @Property(int, notify=totalChanged)
    def total(self): 
        return self._total

    # UI Slots
    @Slot()
    def openImage(self):
        """Open image file dialog."""
        logging.info("Open Image")
        fn, _ = QFileDialog.getOpenFileName(
            None, "Open Image", "", "Images (*.png *.jpg *.jpeg)"
        )
        if not fn:
            return
            
        self._imageUrl = QUrl.fromLocalFile(fn).toString()
        self.imageUrlChanged.emit()
        self._statusText = f"Loaded: {fn}"
        self.statusTextChanged.emit()

    @Slot()
    def openTtl(self):
        """Open TTL file dialog and decrypt."""
        logging.info("Open .ttl")
        fn, _ = QFileDialog.getOpenFileName(
            None, "Open .ttl", "", "ImAged Files (*.ttl)"
        )
        if not fn:
            return
            
        try:
            png, fallback = self._file_manager.open_ttl_file(fn)
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
        """Convert loaded image to TTL with default expiry."""
        logging.info("Default TTL conversion")
        fn = QUrl(self._imageUrl).toLocalFile()
        if not fn:
            self._statusText = "No image loaded"
            self.statusTextChanged.emit()
            return
            
        try:
            out = self._file_manager.create_ttl_file(fn)
            self._statusText = f"Converted: {out}"
        except Exception as e:
            self._statusText = f"Convert failed: {e}"
        self.statusTextChanged.emit()

    @Slot(int, int, int, int, int)
    def convertToTtlCustom(self, year, month, day, hour, minute):
        """Convert loaded image to TTL with custom expiry."""
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
            out = self._file_manager.create_ttl_file(fn, expiry_ts=expiry_ts)
            self._statusText = f"Converted: {out}"
        except Exception as e:
            self._statusText = f"Convert failed: {e}"
        self.statusTextChanged.emit()

    @Slot()
    def saveAsPng(self):
        """Save current image as PNG."""
        logging.info("Save as PNG")
        fn = QUrl(self._imageUrl).toLocalFile()
        if not fn:
            self._statusText = "Nothing to save"
            self.statusTextChanged.emit()
            return
            
        default = Path(fn).stem + "_export.png"
        dest, _ = QFileDialog.getSaveFileName(
            None, "Save As PNG", default, "PNG Files (*.png)"
        )
        if not dest:
            return
            
        try:
            self._file_manager.save_image_as_png(fn, dest)
            self._statusText = f"Saved PNG: {dest}"
        except Exception as e:
            self._statusText = f"Save failed: {e}"
        self.statusTextChanged.emit()

    @Slot(str)
    def batchConvert(self, dirUrl):
        """Batch convert all images in directory."""
        logging.info(f"Batch convert: {dirUrl}")
        folder = QUrl(dirUrl).toLocalFile()
        
        try:
            files = self._file_manager.batch_convert_images(folder)
            self._total = len(files)
            self.totalChanged.emit()
            
            for i, output_path in enumerate(files, 1):
                self._statusText = f"[{i}/{self._total}] Converted: {Path(output_path).name}"
                self._progress = i
                self.progressChanged.emit()
                self.statusTextChanged.emit()
                
            self._statusText = f"Batch done: {self._total} files"
        except Exception as e:
            self._statusText = f"Batch failed: {e}"
        self.statusTextChanged.emit()

    @Slot(str, str, str)
    def savePreferences(self, ttlStr, ntpSrv, outDir):
        """Save user preferences."""
        try:
            ttl = int(ttlStr)
            cfg = {
                "default_ttl_hours": ttl, 
                "ntp_server": ntpSrv, 
                "output_dir": outDir
            }
            save_config(cfg)
            
            self._defaultTtl = ttl
            self._ntpServer = ntpSrv
            self._outputDir = outDir
            
            self.defaultTtlChanged.emit()
            self.ntpServerChanged.emit()
            self.outputDirChanged.emit()
            
            self._statusText = "Preferences saved"
        except Exception as e:
            self._statusText = f"Prefs failed: {e}"
        self.statusTextChanged.emit()