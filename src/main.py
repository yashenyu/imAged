import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
from datetime import datetime, timedelta
import ctypes  
import gc      
from file_manager import TTLFileManager
from secure_image_service import SecureImageService

class SimpleTestUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ImAged Simple Test UI")
        self.ttl_manager = TTLFileManager()
        self.secure_service = SecureImageService()
        self.image_label = tk.Label(root, text="No image loaded", width=40, height=20)
        self.image_label.pack(pady=10)
        self.status_var = tk.StringVar()
        tk.Label(root, textvariable=self.status_var).pack()
        # Date/time entry for expiration
        exp_frame = tk.Frame(root)
        exp_frame.pack(pady=5)
        tk.Label(exp_frame, text="Expiration (YYYY-MM-DD HH:MM):").pack(side=tk.LEFT)
        self.expiry_var = tk.StringVar()
        self.expiry_entry = tk.Entry(exp_frame, textvariable=self.expiry_var, width=20)
        self.expiry_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(exp_frame, text="Now + 1h", command=self.set_default_expiry).pack(side=tk.LEFT)
        self.set_default_expiry()
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Convert Image to TTL", command=self.convert_image).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Open TTL and View", command=self.open_ttl).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Inspect Build Stages", command=self.inspect_build_stages).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Inspect Open Stages", command=self.inspect_open_stages).pack(side=tk.LEFT, padx=5)

        # Inspector view (side-by-side)
        insp_frame = tk.Frame(root)
        insp_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_frame = tk.Frame(insp_frame); right_frame = tk.Frame(insp_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.inspect_left = tk.Text(left_frame, height=22, width=70, wrap=tk.NONE)
        self.inspect_right = tk.Text(right_frame, height=22, width=70, wrap=tk.NONE)
        self.inspect_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.inspect_right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbars (shared vertically)
        scroll_y = tk.Scrollbar(insp_frame, orient=tk.VERTICAL)
        self.inspect_left.configure(yscrollcommand=scroll_y.set)
        self.inspect_right.configure(yscrollcommand=scroll_y.set)
        scroll_y.config(command=self._y_scroll_both)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal scrollbars per pane
        scroll_x_left = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL, command=self.inspect_left.xview)
        scroll_x_right = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL, command=self.inspect_right.xview)
        self.inspect_left.configure(xscrollcommand=scroll_x_left.set)
        self.inspect_right.configure(xscrollcommand=scroll_x_right.set)
        scroll_x_left.pack(side=tk.BOTTOM, fill=tk.X)
        scroll_x_right.pack(side=tk.BOTTOM, fill=tk.X)

        # Emphasis tags
        for t in (self.inspect_left, self.inspect_right):
            t.tag_configure("label", foreground="#0a58ca", font=("Consolas", 10, "bold"))
            t.tag_configure("desc", foreground="#198754")
            t.tag_configure("error", foreground="#dc3545", font=("Consolas", 10, "bold"))
            t.tag_configure("mono", font=("Consolas", 10))
            # Segment color tags (backgrounds kept light for readability)
            t.tag_configure("seg-magic", background="#fff3cd")       # light yellow
            t.tag_configure("seg-salt", background="#d1ecf1")        # light cyan
            t.tag_configure("seg-header", background="#d4edda")      # light green
            t.tag_configure("seg-nonce", background="#e2e3ff")       # light lavender
            t.tag_configure("seg-tag", background="#f8d7da")         # light red
            t.tag_configure("seg-ct", background="#e2e3e5")          # light gray
            t.tag_configure("seg-original", background="#f0f0f0")    # light gray
            t.tag_configure("seg-qoi", background="#e6ffe6")         # pale green
            t.tag_configure("seg-file", background="#f2f2f2")        # very light gray

        self.current_image = None
        self.full_image_window = None
        self._locked_buffers = []

    def set_default_expiry(self):
        dt = datetime.now() + timedelta(hours=1)
        self.expiry_var.set(dt.strftime("%Y-%m-%d %H:%M"))

    def convert_image(self):
        img_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not img_path:
            return
        try:
            expiry_str = self.expiry_var.get().strip()
            expiry_ts = None
            if expiry_str:
                try:
                    dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
                    expiry_ts = int(dt.timestamp())
                except Exception:
                    self.status_var.set("Invalid date/time format. Use YYYY-MM-DD HH:MM")
                    return
            ttl_path = self.ttl_manager.create_ttl_file(img_path, expiry_ts=expiry_ts)
            self.status_var.set(f"Converted to TTL: {ttl_path}")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def open_ttl(self):
        ttl_path = filedialog.askopenfilename(title="Select TTL File", filetypes=[("TTL Files", "*.ttl")])
        if not ttl_path:
            return
        try:
            # Get raw QOI bytes
            qoi_bytes = self.secure_service.render_ttl_image_secure(ttl_path, max_display_time=30)
            if not qoi_bytes:
                raise Exception("Failed to decrypt TTL file or file expired.")

            # Decode QOI to PIL Image
            import qoi, numpy as np
            arr = qoi.decode(qoi_bytes)  # RGBA ndarray
            img = Image.fromarray(arr, mode="RGBA")

            # Show thumbnail in main window
            thumb = img.copy()
            thumb.thumbnail((400, 400))
            self.current_image = ImageTk.PhotoImage(thumb)
            self.image_label.config(image=self.current_image, text="")
            self.status_var.set(f"Opened TTL: {ttl_path}")
            # Show full image in new window
            self.show_full_image(img, ttl_path)
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def inspect_build_stages(self):
        img_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not img_path: return
        try:
            from datetime import datetime
            expiry_str = self.expiry_var.get().strip()
            expiry_ts = None
            if expiry_str:
                dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
                expiry_ts = int(dt.timestamp())
            stages = self.ttl_manager.debug_build_ttl_stages(img_path, expiry_ts)
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self._render_build_stages(stages)
            self.status_var.set("Built TTL stages (annotated).")
        except Exception as e:
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self.inspect_left.insert(tk.END, f"Error: {e}\n", ("error",))
            self.inspect_right.insert(tk.END, f"Error: {e}\n", ("error",))
            self.status_var.set(f"Error: {e}")

    def inspect_open_stages(self):
        ttl_path = filedialog.askopenfilename(title="Select TTL File", filetypes=[("TTL Files", "*.ttl")])
        if not ttl_path: return
        try:
            stages = self.ttl_manager.debug_open_ttl_stages(ttl_path)
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self._render_open_stages(stages)
            self.status_var.set("Opened TTL stages (annotated).")
        except Exception as e:
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self.inspect_left.insert(tk.END, f"Error: {e}\n", ("error",))
            self.inspect_right.insert(tk.END, f"Error: {e}\n", ("error",))
            self.status_var.set(f"Error: {e}")

    def _lock_memory(self, data):
        """Attempt to prevent memory from being swapped to disk (Linux only, best effort)."""
        # WARNING: id(data) is not a pointer to the buffer, so this is not reliable for true security.
        try:
            libc = ctypes.CDLL(None)
            # This is not a secure pointer, but we keep the call for demonstration.
            libc.mlock(ctypes.c_void_p(id(data)), ctypes.c_size_t(len(data)))
            self._locked_buffers.append(data)
        except Exception:
            pass

    def show_full_image(self, img, ttl_path=None):
        if self.full_image_window is not None and tk.Toplevel.winfo_exists(self.full_image_window):
            self.full_image_window.destroy()
        win = tk.Toplevel(self.root)
        win.title("Full Resolution Image")
        # Store original image data for secure cleanup
        img_data = img.tobytes()
        win.original_image_data = img_data
        self._lock_memory(img_data)
        # Set window size
        screen_width = win.winfo_screenwidth()
        screen_height = win.winfo_screenheight()
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)
        # Create main frame
        main_frame = tk.Frame(win)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Calculate scaling
        info_panel_width = 250
        available_width = window_width - info_panel_width - 40
        available_height = window_height - 40
        scale_x = available_width / img.width
        scale_y = available_height / img.height
        scale = min(scale_x, scale_y, 1.0)
        # Resize image
        new_width = int(img.width * scale)
        new_height = int(img.height * scale)
        resized_img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        # Create image display
        image_frame = tk.Frame(main_frame)
        image_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(image_frame, width=new_width, height=new_height)
        canvas.pack(fill=tk.BOTH, expand=True)
        full_img = ImageTk.PhotoImage(resized_img)
        canvas.create_image(new_width//2, new_height//2, anchor=tk.CENTER, image=full_img)
        canvas.image = full_img
        # Info panel
        info_frame = tk.Frame(main_frame, width=info_panel_width, relief=tk.RAISED, borderwidth=2)
        info_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        info_frame.pack_propagate(False)
        # Info panel title
        title_label = tk.Label(info_frame, text="Image Information", font=("Arial", 12, "bold"))
        title_label.pack(pady=(10, 20))
        # Image details
        details_frame = tk.Frame(info_frame)
        details_frame.pack(fill=tk.X, padx=10)
        # Resolution
        resolution_text = f"Resolution: {img.width} × {img.height} pixels"
        tk.Label(details_frame, text=resolution_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # File size (if available)
        if ttl_path and os.path.exists(ttl_path):
            file_size = os.path.getsize(ttl_path)
            size_mb = file_size / (1024 * 1024)
            if size_mb >= 1:
                size_text = f"File Size: {size_mb:.2f} MB"
            else:
                size_kb = file_size / 1024
                size_text = f"File Size: {size_kb:.1f} KB"
            tk.Label(details_frame, text=size_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # Image format
        # Note: img.format is often None when loading from bytes
        format_text = f"Format: {img.format if img.format else 'Unknown (may be None for in-memory images)'}"
        tk.Label(details_frame, text=format_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # Color mode
        mode_text = f"Color Mode: {img.mode}"
        tk.Label(details_frame, text=mode_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # Display size (scaled)
        if scale < 1.0:
            display_text = f"Display Size: {new_width} × {new_height} pixels (scaled {scale:.1%})"
        else:
            display_text = f"Display Size: {new_width} × {new_height} pixels (original size)"
        tk.Label(details_frame, text=display_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # File path (if available)
        if ttl_path:
            path_text = f"File: {os.path.basename(ttl_path)}"
            tk.Label(details_frame, text=path_text, anchor=tk.W).pack(fill=tk.X, pady=2)
        # Separator
        separator = tk.Frame(details_frame, height=2, bg="gray")
        separator.pack(fill=tk.X, pady=10)
        # Secure close logic
        def on_window_close():
            """Securely clean up image data when window closes"""
            try:
                # Clean up locked memory
                for buf in self._locked_buffers:
                    try:
                        libc = ctypes.CDLL(None)
                        libc.munlock(ctypes.c_void_p(id(buf)), ctypes.c_size_t(len(buf)))
                    except Exception:
                        pass
                self._locked_buffers.clear()
                # Zero out image data
                if hasattr(win, 'original_image_data'):
                    mutable_data = bytearray(win.original_image_data)
                    try:
                        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable_data)), 0, len(mutable_data))
                    except Exception:
                        mutable_data[:] = b'\x00' * len(mutable_data)
                    del win.original_image_data
                    del mutable_data
                # Force garbage collection
                for _ in range(3):
                    gc.collect()
            finally:
                win.destroy()
                if self.full_image_window == win:
                    self.full_image_window = None
        # Close button uses secure cleanup
        close_btn = tk.Button(info_frame, text="Close", command=on_window_close, width=15)
        close_btn.pack(pady=10)
        # Center the window on screen
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        win.geometry(f"{window_width}x{window_height}+{x}+{y}")
        win.protocol("WM_DELETE_WINDOW", on_window_close)
        self.full_image_window = win

    def _y_scroll_both(self, *args):
        self.inspect_left.yview(*args)
        self.inspect_right.yview(*args)

    def _fmt_len(self, n):
        if n is None: return "len=0"
        kb = n/1024; mb = kb/1024
        if mb >= 1: return f"len={n} ({mb:.2f} MB)"
        if kb >= 1: return f"len={n} ({kb:.1f} KB)"
        return f"len={n} bytes"

    def _hexdump(self, start_off, data, max_bytes=512):
        if data is None: return ""
        lines = []
        preview = data[:max_bytes]
        for i in range(0, len(preview), 16):
            off = start_off + i
            chunk = preview[i:i+16]
            hexpart = ' '.join(f"{b:02x}" for b in chunk)
            asciipart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{off:08x}  {hexpart:<47}  {asciipart}")
        if len(data) > max_bytes:
            lines.append(f"... ({len(data)-max_bytes} more bytes)")
        return "\n".join(lines) + ("\n" if lines else "")

    def _append_section_to(self, widget, title, desc, start_off, data, seg_tag: str):
        # Remember start index
        start_idx = widget.index(tk.END)
        # Header line
        widget.insert(tk.END, f"{title} ", ("label", seg_tag))
        widget.insert(tk.END, f"({self._fmt_len(len(data))}, offset={start_off})\n", ("mono", seg_tag))
        if desc:
            widget.insert(tk.END, f"  {desc}\n", ("desc", seg_tag))
        # Hex dump
        hex_text = self._hexdump(start_off, data)
        widget.insert(tk.END, hex_text, ("mono", seg_tag))

    def _append_field_to(self, widget, title, value):
        widget.insert(tk.END, f"{title}: ", ("label",))
        widget.insert(tk.END, f"{value}\n", ("mono",))

    def _render_build_stages(self, stages):
        L, R = self.inspect_left, self.inspect_right
        L.delete(1.0, tk.END); R.delete(1.0, tk.END)

        # Left (source)
        self._append_section_to(L, "original", "Original source image bytes as read", 0, stages["original"], "seg-original")
        self._append_section_to(L, "qoi", "QOI-encoded image bytes (plaintext before encryption)", 0, stages["qoi"], "seg-qoi")

        # Right (TTL layout)
        off = 0; MAGIC = b"IMAGED"
        self._append_section_to(R, "MAGIC", "File marker", off, MAGIC, "seg-magic"); off += len(MAGIC)
        self._append_section_to(R, "salt", "HKDF salt for CEK/HDR keys", off, stages["salt"], "seg-salt"); off += 16
        self._append_section_to(R, "nonce_hdr", "GCM nonce for header tag", off, stages["nonce_hdr"], "seg-nonce"); off += 12
        self._append_section_to(R, "header", "expiry_ts (8-byte big-endian)", off, stages["header"], "seg-header"); off += 8
        import struct, datetime as _dt
        expiry_ts = struct.unpack(">Q", stages["header"])[0]
        self._append_field_to(R, "expiry_ts", f"{expiry_ts} ({_dt.datetime.fromtimestamp(expiry_ts)})")
        self._append_section_to(R, "tag_hdr", "AES-GCM tag authenticating header (AAD=header, P=empty)", off, stages["tag_hdr"], "seg-tag"); off += 16
        self._append_section_to(R, "nonce_body", "GCM nonce for body", off, stages["nonce_body"], "seg-nonce"); off += 12
        self._append_section_to(R, "tag_body", "AES-GCM tag for body (AAD=header)", off, stages["tag_body"], "seg-tag"); off += 16
        self._append_section_to(R, "ciphertext_body", "Encrypted QOI bytes", off, stages["ciphertext_body"], "seg-ct")

    def _render_open_stages(self, stages):
        L, R = self.inspect_left, self.inspect_right
        L.delete(1.0, tk.END); R.delete(1.0, tk.END)

        # Left: raw file
        self._append_section_to(L, "file_bytes", "Raw TTL file bytes", 0, stages["file_bytes"], "seg-file")

        # Right: parsed segments
        off = 0
        MAGIC = stages["file_bytes"][:6]
        self._append_section_to(R, "MAGIC", "File marker", off, MAGIC, "seg-magic"); off += len(MAGIC)
        self._append_section_to(R, "salt", "HKDF salt for CEK/HDR keys", off, stages["salt"], "seg-salt"); off += 16
        self._append_section_to(R, "nonce_hdr", "GCM nonce for header tag", off, stages["nonce_hdr"], "seg-nonce"); off += 12
        self._append_section_to(R, "header", "expiry_ts (8-byte big-endian)", off, stages["header"], "seg-header"); off += 8
        import struct, datetime as _dt
        expiry_ts = struct.unpack(">Q", stages["header"])[0]
        self._append_field_to(R, "expiry_ts", f"{expiry_ts} ({_dt.datetime.fromtimestamp(expiry_ts)})")
        self._append_section_to(R, "tag_hdr", "AES-GCM tag authenticating header", off, stages["tag_hdr"], "seg-tag"); off += 16
        self._append_section_to(R, "nonce_body", "GCM nonce for body", off, stages["nonce_body"], "seg-nonce"); off += 12
        self._append_section_to(R, "tag_body", "AES-GCM tag for body (AAD=header)", off, stages["tag_body"], "seg-tag"); off += 16
        self._append_section_to(R, "ciphertext_body", "Encrypted QOI bytes", off, stages["ciphertext_body"], "seg-ct")
        self._append_section_to(R, "qoi", "Decrypted QOI bytes (plaintext after decryption)", 0, stages["qoi"], "seg-qoi")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleTestUI(root)
    root.mainloop()
