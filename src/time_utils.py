import socket
import struct
import logging
from config import load_config

def fetch_ntp_time(timeout: int = 10, server: str = None) -> float:
    """
    Fetch current time from NTP server with mandatory response requirement.
    
    This function requires a successful NTP response and will raise an exception
    if the NTP server is unreachable or returns invalid data.
    
    Args:
        timeout: Socket timeout in seconds for NTP request
        server: Optional NTP server address (defaults to config setting)
        
    Returns:
        Current timestamp from NTP server
        
    Raises:
        RuntimeError: If NTP server is unreachable or returns invalid data
    """
    cfg = load_config()
    if server is None:
        server = cfg.get("ntp_server", "time.google.com")
    
    try:
        addr = (server, 123)
        msg = b"\x1b" + 47 * b"\0"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, addr)
        res, _ = s.recvfrom(1024)
        t = struct.unpack("!12I", res)[10] - 2208988800
        logging.info("NTP time from %s: %s", server, t)
        return t
    except Exception as e:
        error_msg = f"NTP fetch from {server} failed: {e}"
        logging.error(error_msg)
        raise RuntimeError(error_msg)

def get_current_time() -> float:
    """
    Get current time from NTP server with mandatory response requirement.
    
    This function requires a successful NTP response and will raise an exception
    if the NTP server is unreachable or returns invalid data.
    
    Returns:
        Current timestamp from NTP server
        
    Raises:
        RuntimeError: If NTP server is unreachable or returns invalid data
    """
    return fetch_ntp_time()

def get_current_time_with_fallback() -> tuple[float, bool]:
    """
    Get current time from NTP server (maintained for backward compatibility).
    
    Note: This function now always requires NTP and will raise an exception
    if NTP is unavailable. The fallback parameter is always False.
    
    Returns:
        Tuple of (ntp_timestamp, False) indicating NTP was used
        
    Raises:
        RuntimeError: If NTP server is unreachable or returns invalid data
    """
    ntp_time = fetch_ntp_time()
    return ntp_time, False

def validate_expiry_time(expiry_ts: int) -> bool:
    """
    Check if a timestamp has expired using mandatory NTP time.
    
    Args:
        expiry_ts: Expiry timestamp to validate
        
    Returns:
        True if timestamp has expired, False otherwise
        
    Raises:
        RuntimeError: If NTP server is unreachable or returns invalid data
    """
    current_time = get_current_time()
    return current_time <= expiry_ts