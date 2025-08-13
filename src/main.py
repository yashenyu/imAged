import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
from datetime import datetime, timedelta
import ctypes  
import gc      
import time
import logging
from file_manager import TTLFileManager
from secure_image_service import SecureImageService
from config import load_config

# Configure logging to actually show in console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('imaged.log')
    ]
)

def check_ntp_availability():
    """
    Verify NTP server availability before application startup.
    
    This function ensures that the configured NTP server is reachable
    and can provide accurate time synchronization.
    
    Raises:
        RuntimeError: If NTP server is unreachable or returns invalid data
    """
    try:
        from time_utils import get_current_time
        current_time = get_current_time()
        logging.info(f"NTP check successful - Current time: {current_time}")
        print(f"NTP check successful - Current time: {current_time}")
        return True
    except Exception as e:
        error_msg = f"NTP check failed: {e}"
        logging.error(error_msg)
        print(f"{error_msg}")
        raise RuntimeError(error_msg)

# Perform NTP availability check at startup
try:
    check_ntp_availability()
except RuntimeError as e:
    print(f"Critical: Application cannot start without NTP access: {e}")
    print("Please check your internet connection and NTP server configuration.")
    sys.exit(1)

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
        
        # QOI Conversion toggle
        qoi_frame = tk.Frame(root)
        qoi_frame.pack(pady=5)
        self.qoi_var = tk.BooleanVar(value=self.ttl_manager.enable_qoi)
        qoi_check = tk.Checkbutton(qoi_frame, text="Enable QOI Conversion", variable=self.qoi_var, 
                                  command=self.update_qoi_status)
        qoi_check.pack(side=tk.LEFT)
        
        # NTP Status and Test
        ntp_frame = tk.Frame(root)
        ntp_frame.pack(pady=5)
        tk.Label(ntp_frame, text="NTP Status:").pack(side=tk.LEFT)
        self.ntp_status_var = tk.StringVar(value="Checking...")
        ntp_status_label = tk.Label(ntp_frame, textvariable=self.ntp_status_var, fg="blue")
        ntp_status_label.pack(side=tk.LEFT, padx=5)
        ntp_test_btn = tk.Button(ntp_frame, text="Test NTP", command=self.test_ntp_connection)
        ntp_test_btn.pack(side=tk.LEFT, padx=5)
        ntp_config_btn = tk.Button(ntp_frame, text="Config", command=self.show_config_dialog)
        ntp_config_btn.pack(side=tk.LEFT, padx=5)
        
        # Update NTP status
        self.update_ntp_status()
        
        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Convert Image to TTL", command=self.convert_image).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Open TTL File", command=self.open_ttl).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Inspect Build Stages", command=self.inspect_build_stages).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Inspect Open Stages", command=self.inspect_open_stages).pack(side=tk.LEFT, padx=5)

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
        """Set default expiry time to 1 hour from now."""
        default_expiry = datetime.now() + timedelta(hours=1)
        self.expiry_var.set(default_expiry.strftime("%Y-%m-%d %H:%M"))
    
    def update_qoi_status(self):
        """Update QOI conversion status and refresh TTL manager configuration."""
        self.ttl_manager.enable_qoi = self.qoi_var.get()
        status_text = "ENABLED" if self.qoi_var.get() else "DISABLED"
        self.status_var.set(f"QOI Conversion: {status_text}")
        logging.info(f"QOI conversion setting updated: {status_text}")
    
    def update_ntp_status(self):
        """Update NTP status display with current connection status."""
        try:
            from time_utils import get_current_time
            current_time = get_current_time()
            from datetime import datetime
            time_str = datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S")
            self.ntp_status_var.set(f"Connected - {time_str}")
            self.ntp_status_var.set("Connected")
        except Exception as e:
            self.ntp_status_var.set("Failed")
            logging.error(f"NTP status check failed: {e}")
    
    def test_ntp_connection(self):
        """Test NTP connection and display current time for user verification."""
        try:
            from time_utils import get_current_time
            current_time = get_current_time()
            from datetime import datetime
            time_str = datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S")
            
            messagebox.showinfo("NTP Test", 
                              f"NTP connection successful!\n\n"
                              f"Current NTP time: {time_str}\n"
                              f"Timestamp: {current_time}")
            
            # Update status display
            self.ntp_status_var.set("Connected")
            logging.info(f"NTP test successful - Current time: {time_str}")
            
        except Exception as e:
            error_msg = f"NTP test failed: {e}"
            messagebox.showerror("NTP Test Failed", error_msg)
            self.ntp_status_var.set("Failed")
            logging.error(error_msg)
    
    def refresh_ttl_manager_config(self):
        """Refresh TTL manager configuration from config file."""
        try:
            from config import load_config
            new_config = load_config()
            self.ttl_manager.cfg = new_config
            self.ttl_manager.enable_qoi = bool(new_config.get("enable_qoi", False))
            logging.info("TTL manager configuration refreshed")
        except Exception as e:
            logging.error(f"Failed to refresh TTL manager configuration: {e}")
            messagebox.showerror("Configuration Error", f"Failed to refresh configuration: {e}")
    
    def show_config_dialog(self):
        """Show configuration dialog for modifying NTP server and other settings."""
        config_dialog = tk.Toplevel(self.root)
        config_dialog.title("Configuration")
        config_dialog.geometry("400x300")
        config_dialog.transient(self.root)
        config_dialog.grab_set()
        
        # Load current configuration
        try:
            current_config = load_config()
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to load configuration: {e}")
            return
        
        # NTP Server configuration
        ntp_frame = tk.Frame(config_dialog)
        ntp_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Label(ntp_frame, text="NTP Server:").pack(anchor=tk.W)
        ntp_server_var = tk.StringVar(value=current_config.get("ntp_server", "time.google.com"))
        ntp_entry = tk.Entry(ntp_frame, textvariable=ntp_server_var, width=40)
        ntp_entry.pack(fill=tk.X, pady=2)
        
        # TTL Hours configuration
        ttl_frame = tk.Frame(config_dialog)
        ttl_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Label(ttl_frame, text="Default TTL Hours:").pack(anchor=tk.W)
        ttl_hours_var = tk.StringVar(value=str(current_config.get("default_ttl_hours", 1)))
        ttl_entry = tk.Entry(ttl_frame, textvariable=ttl_hours_var, width=40)
        ttl_entry.pack(fill=tk.X, pady=2)
        
        # QOI configuration
        qoi_frame = tk.Frame(config_dialog)
        qoi_frame.pack(fill=tk.X, padx=20, pady=10)
        qoi_var = tk.BooleanVar(value=current_config.get("enable_qoi", False))
        qoi_check = tk.Checkbutton(qoi_frame, text="Enable QOI Conversion", variable=qoi_var)
        qoi_check.pack(anchor=tk.W)
        
        # Output directory configuration
        output_frame = tk.Frame(config_dialog)
        output_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Label(output_frame, text="Output Directory (optional):").pack(anchor=tk.W)
        output_dir_var = tk.StringVar(value=current_config.get("output_dir", ""))
        output_entry = tk.Entry(output_frame, textvariable=output_dir_var, width=40)
        output_entry.pack(fill=tk.X, pady=2)
        
        # Buttons
        button_frame = tk.Frame(config_dialog)
        button_frame.pack(pady=20)
        
        def save_config():
            """Save configuration and validate NTP connectivity."""
            try:
                # Validate TTL hours
                ttl_hours = float(ttl_hours_var.get())
                if ttl_hours <= 0:
                    raise ValueError("TTL hours must be a positive number")
                
                # Create new configuration
                new_config = {
                    "ntp_server": ntp_server_var.get().strip(),
                    "default_ttl_hours": ttl_hours,
                    "enable_qoi": qoi_var.get(),
                    "output_dir": output_dir_var.get().strip()
                }
                
                # Test NTP connectivity with new server
                from time_utils import fetch_ntp_time
                test_time = fetch_ntp_time(server=new_config["ntp_server"])
                if test_time is None:
                    raise RuntimeError(f"Failed to connect to NTP server: {new_config['ntp_server']}")
                
                # Save configuration
                from config import save_config as save_config_file
                save_config_file(new_config)
                
                # Update TTL manager configuration
                self.ttl_manager.cfg = new_config
                self.ttl_manager.enable_qoi = new_config["enable_qoi"]
                
                # Refresh TTL manager with new configuration
                self.refresh_ttl_manager_config()
                
                # Update QOI checkbox
                self.qoi_var.set(new_config["enable_qoi"])
                
                # Update NTP status
                self.update_ntp_status()
                
                messagebox.showinfo("Success", "Configuration saved successfully!")
                config_dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Configuration Error", f"Failed to save configuration: {e}")
        
        def test_ntp():
            """Test NTP connectivity with current server setting."""
            try:
                from time_utils import fetch_ntp_time
                test_time = fetch_ntp_time(server=ntp_server_var.get().strip())
                if test_time is not None:
                    from datetime import datetime
                    time_str = datetime.fromtimestamp(test_time).strftime("%Y-%m-%d %H:%M:%S")
                    messagebox.showinfo("NTP Test", 
                                      f"NTP connection successful!\n\n"
                                      f"Server: {ntp_server_var.get().strip()}\n"
                                      f"Current time: {time_str}")
                else:
                    messagebox.showerror("NTP Test", "Failed to connect to NTP server")
            except Exception as e:
                messagebox.showerror("NTP Test", f"NTP test failed: {e}")
        
        tk.Button(button_frame, text="Test NTP", command=test_ntp).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Save", command=save_config).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=config_dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _log_timing(self, step_name, start_time, data_size=None):
        """
        Log timing information for a process step with performance metrics.
        
        Args:
            step_name: Name of the process step being timed
            start_time: Timestamp when the step began
            data_size: Optional data size in bytes for throughput calculation
        """
        elapsed = time.time() - start_time
        if data_size:
            size_mb = data_size / (1024 * 1024)
            speed = size_mb / elapsed if elapsed > 0 else 0
            message = f"{step_name}: {elapsed:.3f}s | {size_mb:.2f} MB | {speed:.2f} MB/s"
        else:
            message = f"{step_name}: {elapsed:.3f}s"
        
        # Ensure visibility through both logging and console output
        logging.info(message)
        print(f"  {message}")

    def convert_image(self):
        """
        Convert selected image to TTL format with comprehensive timing analysis.
        
        This method performs the complete TTL conversion pipeline including:
        - Expiry time parsing and validation
        - TTL file creation with encryption
        - Performance metrics and file size analysis
        """
        img_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not img_path:
            return
        
        total_start = time.time()
        print(f"Starting TTL conversion for: {os.path.basename(img_path)}")
        logging.info(f"Starting TTL conversion for: {os.path.basename(img_path)}")
        
        try:
            # Parse and validate expiry time specification
            step_start = time.time()
            expiry_str = self.expiry_var.get().strip()
            expiry_ts = None
            if expiry_str:
                try:
                    dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
                    expiry_ts = int(dt.timestamp())
                except Exception:
                    self.status_var.set("Invalid date/time format. Use YYYY-MM-DD HH:MM")
                    return
            self._log_timing("Parse expiry time", step_start)
            
            # Execute TTL file creation with encryption
            step_start = time.time()
            ttl_path = self.ttl_manager.create_ttl_file(img_path, expiry_ts=expiry_ts)
            self._log_timing("Create TTL file", step_start)
            
            # Analyze compression performance and file characteristics
            if os.path.exists(ttl_path):
                file_size = os.path.getsize(ttl_path)
                input_size = os.path.getsize(img_path)
                compression_ratio = input_size / file_size if file_size > 0 else 0
                size_message = f"File sizes: Input: {input_size/1024:.1f} KB | Output: {file_size/1024:.1f} KB | Ratio: {compression_ratio:.2f}x"
                logging.info(size_message)
                print(size_message)
            
            total_elapsed = time.time() - total_start
            completion_message = f"TTL conversion completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            self.status_var.set(f"Converted to TTL: {ttl_path}")
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"TTL conversion failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def open_ttl(self):
        """
        Open and decrypt TTL file with comprehensive performance analysis.
        
        This method implements the complete TTL decryption pipeline including:
        - Secure file loading and decryption
        - Image format interpretation based on configuration
        - Performance metrics for each processing stage
        - Memory-efficient image rendering
        """
        ttl_path = filedialog.askopenfilename(title="Select TTL File", filetypes=[("TTL Files", "*.ttl")])
        if not ttl_path:
            return
        
        total_start = time.time()
        print(f"Starting TTL opening for: {os.path.basename(ttl_path)}")
        logging.info(f"Starting TTL opening for: {os.path.basename(ttl_path)}")
        
        try:
            # Obtain file metadata for performance analysis
            step_start = time.time()
            file_size = os.path.getsize(ttl_path)
            self._log_timing("Get file size", step_start)
            
            # Execute secure TTL decryption in memory
            step_start = time.time()
            payload_bytes = self.secure_service.render_ttl_image_secure(ttl_path, max_display_time=30)
            if not payload_bytes:
                raise Exception("Failed to decrypt TTL file or file expired.")
            self._log_timing("Decrypt TTL file", step_start, len(payload_bytes))
            
            # Interpret decrypted payload based on configuration settings
            step_start = time.time()
            enable_qoi = bool(self.ttl_manager.enable_qoi)
            if enable_qoi:
                # Decode QOI format to PIL Image object
                import qoi
                arr = qoi.decode(payload_bytes)  # RGBA ndarray
                img = Image.fromarray(arr, mode="RGBA")
                pixel_message = f"Decoded QOI: {arr.shape[1]}x{arr.shape[0]} pixels"
                logging.info(pixel_message)
                print(pixel_message)
            else:
                # Load original image format directly from bytes
                import io
                img = Image.open(io.BytesIO(payload_bytes)).convert("RGBA")
                pixel_message = f"Loaded original: {img.width}x{img.height} pixels"
                logging.info(pixel_message)
                print(pixel_message)
            self._log_timing("Image interpretation", step_start)
            
            # Generate thumbnail for UI display
            step_start = time.time()
            thumb = img.copy()
            thumb.thumbnail((400, 400))
            self.current_image = ImageTk.PhotoImage(thumb)
            self.image_label.config(image=self.current_image, text="")
            self._log_timing("Create thumbnail", step_start)
            
            # Display full-resolution image in separate window
            step_start = time.time()
            self.show_full_image(img, ttl_path)
            self._log_timing("Show full image", step_start)
            
            total_elapsed = time.time() - total_start
            completion_message = f"TTL opening completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            self.status_var.set(f"Opened TTL: {ttl_path}")
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"TTL opening failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def inspect_build_stages(self):
        """
        Analyze TTL file creation process through detailed stage inspection.
        
        This method provides comprehensive analysis of the TTL creation pipeline:
        - Original image analysis and metadata extraction
        - Payload preparation and format conversion
        - Cryptographic material generation and key derivation
        - Header authentication and body encryption
        - Final file structure assembly
        """
        img_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not img_path: return
        
        total_start = time.time()
        print(f"Starting build stage inspection for: {os.path.basename(img_path)}")
        logging.info(f"Starting build stage inspection for: {os.path.basename(img_path)}")
        
        try:
            # Parse and validate expiry time specification
            step_start = time.time()
            from datetime import datetime
            expiry_str = self.expiry_var.get().strip()
            expiry_ts = None
            if expiry_str:
                dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M")
                expiry_ts = int(dt.timestamp())
            self._log_timing("Parse expiry time", step_start)
            
            # Execute comprehensive TTL stage analysis
            step_start = time.time()
            stages = self.ttl_manager.debug_build_ttl_stages(img_path, expiry_ts)
            self._log_timing("Build TTL stages", step_start)
            
            # Render analysis results in user interface
            step_start = time.time()
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self._render_build_stages(stages)
            self._log_timing("Render stages in UI", step_start)
            
            total_elapsed = time.time() - total_start
            completion_message = f"Build stage inspection completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            self.status_var.set("Built TTL stages (annotated).")
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"Build stage inspection failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self.inspect_left.insert(tk.END, f"Error: {e}\n", ("error",))
            self.inspect_right.insert(tk.END, f"Error: {e}\n", ("error",))
            self.status_var.set(f"Error: {e}")

    def inspect_open_stages(self):
        """
        Analyze TTL file decryption process through detailed stage inspection.
        
        This method provides comprehensive analysis of the TTL decryption pipeline:
        - File structure parsing and segment extraction
        - Header verification and authentication
        - Body decryption and payload recovery
        - Performance metrics for each processing stage
        """
        ttl_path = filedialog.askopenfilename(title="Select TTL File", filetypes=[("TTL Files", "*.ttl")])
        if not ttl_path: return
        
        total_start = time.time()
        print(f"Starting open stage inspection for: {os.path.basename(ttl_path)}")
        logging.info(f"Starting open stage inspection for: {os.path.basename(ttl_path)}")
        
        try:
            # Execute comprehensive TTL stage analysis
            step_start = time.time()
            stages = self.ttl_manager.debug_open_ttl_stages(ttl_path)
            self._log_timing("Open TTL stages", step_start)
            
            # Render analysis results in user interface
            step_start = time.time()
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self._render_open_stages(stages)
            self._log_timing("Render stages in UI", step_start)
            
            total_elapsed = time.time() - total_start
            completion_message = f"Open stage inspection completed in {total_elapsed:.3f}s"
            logging.info(completion_message)
            print(completion_message)
            self.status_var.set("Opened TTL stages (annotated).")
            
        except Exception as e:
            total_elapsed = time.time() - total_start
            error_message = f"Open stage inspection failed after {total_elapsed:.3f}s: {e}"
            logging.error(error_message)
            print(error_message)
            self.inspect_left.delete(1.0, tk.END); self.inspect_right.delete(1.0, tk.END)
            self.inspect_left.insert(tk.END, f"Error: {e}\n", ("error",))
            self.inspect_right.insert(tk.END, f"Error: {e}\n", ("error",))
            self.status_var.set(f"Error: {e}")

    def _lock_memory(self, data):
        """Attempt to prevent memory from being swapped to disk (Linux only, best effort)."""
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
        # Describe payload depending on config
        payload_desc = "QOI-encoded image bytes (plaintext before encryption)" if self.ttl_manager.enable_qoi else "Original image bytes (plaintext before encryption)"
        self._append_section_to(L, "payload", payload_desc, 0, stages["payload"], "seg-qoi")

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
        self._append_section_to(R, "ciphertext_body", "Encrypted payload bytes", off, stages["ciphertext_body"], "seg-ct")

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
        self._append_section_to(R, "ciphertext_body", "Encrypted payload bytes", off, stages["ciphertext_body"], "seg-ct")
        payload_desc = "Decrypted QOI bytes (plaintext after decryption)" if self.ttl_manager.enable_qoi else "Decrypted original image bytes (plaintext after decryption)"
        self._append_section_to(R, "payload", payload_desc, 0, stages["payload"], "seg-qoi")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleTestUI(root)
    root.mainloop()
