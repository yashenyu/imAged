import struct
import qoi
import base64
import numpy as np
import time

from pathlib import Path
from PIL import Image
from io import BytesIO

from ntplib import NTPClient, NTPException
from PySide6.QtWidgets import QFileDialog
from PySide6.QtCore import QObject, Slot, Property, Signal

class PythonAPI(QObject):
    imageUrlChanged = Signal()
    statusTextChanged = Signal()

    def __init__(self):
        super().__init__()
        self._imageUrl = ""
        self._statusText = "Ready"

    @Property(str, notify=imageUrlChanged)
    def imageUrl(self):
        return self._imageUrl

    @Property(str, notify=statusTextChanged)
    def statusText(self):
        return self._statusText

    def _updateStatus(self, text: str):
        self._statusText = text
        self.statusTextChanged.emit()

    @Slot()
    def openFile(self):
        # 1) Let user pick a .ttl
        filename, _ = QFileDialog.getOpenFileName(
            None, "Open ImAged .ttl", "", "ImAged Files (*.ttl)"
        )
        if not filename:
            self._updateStatus("No file selected")
            return

        try:
            # 2) Read and validate header
            with open(filename, "rb") as f:
                hdr = f.read(28)
                if len(hdr) < 28:
                    raise ValueError("Invalid file format: header too short")
                
                magic, version, flags, created, expiry, length = struct.unpack(">4s B 3s Q Q I", hdr)
                
                # Validate magic number
                if magic != b"IMAG":
                    raise ValueError("Invalid file format: wrong magic number")
                
                # Validate version
                if version != 1:
                    raise ValueError(f"Unsupported version: {version}")

            # 3) Get authoritative time via NTP (fallback to local clock)
            try:
                client = NTPClient()
                response = client.request("pool.ntp.org", version=3)
                now = response.tx_time
            except (NTPException, OSError):
                now = time.time()
                self._updateStatus("Warning: Using local clock")

            # 4) Enforce TTL
            if now > expiry:
                self._updateStatus("Error: File has expired")
                return

            # 5) Read and decode payload
            with open(filename, "rb") as f:
                f.seek(28)
                payload = f.read(length)
                if len(payload) != length:
                    raise ValueError("Invalid file format: payload length mismatch")

            try:
                arr = qoi.decode(payload)
            except Exception as e:
                raise ValueError(f"Failed to decode QOI data: {str(e)}")

            # 6) Convert to PNG data URL
            img = Image.fromarray(np.array(arr, dtype=np.uint8), mode="RGBA")
            buf = BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()

            self._imageUrl = f"data:image/png;base64,{b64}"
            self._updateStatus("Loaded successfully")

        except Exception as e:
            self._updateStatus(f"Error: {str(e)}")
            self._imageUrl = ""  # Clear the image on error
            self.imageUrlChanged.emit()

        # 7) Notify QML of property updates
        self.imageUrlChanged.emit() 