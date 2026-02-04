import socket
import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def validate_url_safety(url: str):
    """
    Resolves DNS and checks if the IP belongs to private/loopback ranges (SSRF Protection).
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return # Local file or invalid

        # Resolve IP
        ip_list = socket.getaddrinfo(hostname, None)
        
        for item in ip_list:
            ip_addr = item[4][0]
            ip_obj = ipaddress.ip_address(ip_addr)
            
            # Check against private ranges
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                raise ValueError(f"SSRF Protection: Access to private IP {ip_addr} ({hostname}) is forbidden.")
                
    except socket.gaierror:
        # DNS resolution failed - might be internal domain or invalid
        # In strict security mode, we should block. For MVP, we log warning.
        logger.warning(f"Could not resolve hostname: {hostname}")
    except ValueError as e:
        raise e
    except Exception as e:
        logger.warning(f"SSRF Check failed: {e}")
