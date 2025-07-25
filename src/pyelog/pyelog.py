"""
PyElog - A Python library for interacting with ELOG (Electronic Logbook) servers.

This library provides functionality to submit and retrieve entries from ELOG servers,
replicating the protocol used in the original C++ implementation.
"""

import socket
import ssl
import random
import time
import urllib.parse
import hashlib
from typing import Dict, List, Optional, Tuple, Union, BinaryIO, Sequence


class ElogError(Exception):
    """Base exception for ELOG-related errors."""
    pass


class ElogConnectionError(ElogError):
    """Exception raised when connection to ELOG server fails."""
    pass


class ElogAuthenticationError(ElogError):
    """Exception raised when authentication fails."""
    pass


class ElogSubmissionError(ElogError):
    """Exception raised when message submission fails."""
    pass


class ElogRetrievalError(ElogError):
    """Exception raised when message retrieval fails."""
    pass


class ElogClient:
    """
    A client for interacting with ELOG (Electronic Logbook) servers.
    
    This class provides methods to submit and retrieve logbook entries,
    replicating the protocol used by the original ELOG C++ client.
    """
    
    def __init__(self, hostname: str, port: int = 80, use_ssl: bool = False, 
                 subdir: str = "", username: str = "", password: str = "",
                 verbose: bool = False):
        """
        Initialize the ELOG client.
        
        Args:
            hostname: The hostname of the ELOG server
            port: The port number (default: 80 for HTTP, 443 for HTTPS)
            use_ssl: Whether to use SSL/TLS encryption
            subdir: Subdirectory path on the server
            username: Username for authentication
            password: Password for authentication
            verbose: Enable verbose output for debugging
        """
        self.hostname = hostname
        self.port = port if port else (443 if use_ssl else 80)
        self.use_ssl = use_ssl
        self.subdir = subdir.strip('/')
        self.username = username
        self.password = password
        self.verbose = verbose
        
    def _connect(self) -> socket.socket:
        """
        Establish connection to the ELOG server.
        
        Returns:
            Connected socket object
            
        Raises:
            ElogConnectionError: If connection fails
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # 30 second timeout
            
            # Connect to server
            sock.connect((self.hostname, self.port))
            
            # Wrap with SSL if needed
            if self.use_ssl:
                context = ssl.create_default_context()
                # For testing, you might want to disable certificate verification
                # context.check_hostname = False
                # context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.hostname)
                
            return sock
            
        except Exception as e:
            raise ElogConnectionError(f"Failed to connect to {self.hostname}:{self.port}: {e}")
    
    def _send_request(self, sock: socket.socket, request: str) -> None:
        """Send HTTP request to the server."""
        if self.verbose:
            print("Request sent to host:")
            print(request)
        sock.sendall(request.encode('utf-8'))
    
    def _send_data(self, sock: socket.socket, data: bytes) -> None:
        """Send binary data to the server."""
        if self.verbose:
            print(f"Sending {len(data)} bytes of data")
        sock.sendall(data)
    
    def _receive_response(self, sock: socket.socket) -> str:
        """
        Receive complete HTTP response from the server.
        
        Returns:
            Complete HTTP response as string
        """
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        response_str = response.decode('utf-8', errors='ignore')
        
        if self.verbose:
            print("Response received:")
            print(response_str)
            
        return response_str
    
    def _url_encode(self, text: str) -> str:
        """URL encode a string."""
        return urllib.parse.quote(text, safe='')
    
    def _generate_boundary(self) -> str:
        """Generate a random boundary for multipart/form-data."""
        random.seed(time.time())
        return f"---------------------------{random.randint(0, 0xFFFF):04X}{random.randint(0, 0xFFFF):04X}{random.randint(0, 0xFFFF):04X}"
    
    def _encrypt_password(self, password: str) -> str:
        """
        Encrypt password using SHA256-based crypt method (matches ELOG protocol).
        
        This implementation replicates the sha256_crypt function from ELOG's crypt.cxx
        and the do_crypt function from elogd.cxx:
        do_crypt(s, d, size) { strlcpy(d, sha256_crypt(s, "$5$") + 4, size); }
        
        Returns the hash without the "$5$" prefix, exactly as ELOG does.
        """
        if not password:
            return ""
        
        return self._sha256_crypt(password, "$5$")[4:]  # Remove "$5$" prefix
    
    def _sha256_crypt(self, password: str, salt: str) -> str:
        """
        Pure Python implementation of SHA256-based crypt, replicating ELOG's crypt.cxx
        
        This follows the exact algorithm from the C++ implementation:
        - Uses the same constants, rounds, and encoding
        - Produces identical output to the original sha256_crypt function
        - Uses only standard library hashlib (no deprecated crypt module)
        - Future-proof implementation compatible with Python 3.13+
        """
        # Constants from crypt.cxx
        SALT_PREFIX = "$5$"
        ROUNDS_DEFAULT = 5000
        SALT_LEN_MAX = 16
        B64T = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        
        # Parse salt (remove prefix if present)
        if salt.startswith(SALT_PREFIX):
            salt = salt[len(SALT_PREFIX):]
        
        # Extract salt (up to first $ or max length)
        salt_end = salt.find('$')
        if salt_end >= 0:
            salt = salt[:salt_end]
        salt = salt[:SALT_LEN_MAX]
        
        key = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        key_len = len(key)
        salt_len = len(salt_bytes)
        rounds = ROUNDS_DEFAULT
        
        # Step 1: Initial hash with key + salt + key
        ctx = hashlib.sha256()
        ctx.update(key)
        ctx.update(salt_bytes)
        
        # Alternate context: key + salt + key
        alt_ctx = hashlib.sha256()
        alt_ctx.update(key)
        alt_ctx.update(salt_bytes)
        alt_ctx.update(key)
        alt_result = alt_ctx.digest()
        
        # Add alternate result to main context
        for i in range(0, key_len, 32):
            ctx.update(alt_result[:min(32, key_len - i)])
        
        # Add key or alt_result based on key length bits
        temp_key_len = key_len
        while temp_key_len > 0:
            if temp_key_len & 1:
                ctx.update(alt_result)
            else:
                ctx.update(key)
            temp_key_len >>= 1
        
        alt_result = ctx.digest()
        
        # Create P sequence
        p_ctx = hashlib.sha256()
        for _ in range(key_len):
            p_ctx.update(key)
        p_bytes = p_ctx.digest()
        
        # Create S sequence
        s_ctx = hashlib.sha256()
        for _ in range(16 + alt_result[0]):
            s_ctx.update(salt_bytes)
        s_bytes = s_ctx.digest()
        
        # Main iteration loop
        for i in range(rounds):
            ctx = hashlib.sha256()
            
            # Add key or previous result
            if i & 1:
                # Add P bytes (key)
                for j in range(0, key_len, 32):
                    ctx.update(p_bytes[:min(32, key_len - j)])
            else:
                ctx.update(alt_result)
            
            # Add salt for numbers not divisible by 3
            if i % 3 != 0:
                for j in range(0, salt_len, 32):
                    ctx.update(s_bytes[:min(32, salt_len - j)])
            
            # Add key for numbers not divisible by 7
            if i % 7 != 0:
                for j in range(0, key_len, 32):
                    ctx.update(p_bytes[:min(32, key_len - j)])
            
            # Add previous result or key
            if i & 1:
                ctx.update(alt_result)
            else:
                for j in range(0, key_len, 32):
                    ctx.update(p_bytes[:min(32, key_len - j)])
            
            alt_result = ctx.digest()
        
        # Build result string: $5$ + salt + $ + base64_encoded_hash
        def b64_from_24bit(b2, b1, b0, n):
            w = (b2 << 16) | (b1 << 8) | b0
            result = ""
            for _ in range(n):
                result += B64T[w & 0x3f]
                w >>= 6
            return result
        
        # Encode the hash using the same pattern as crypt.cxx
        encoded = ""
        encoded += b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4)
        encoded += b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4)
        encoded += b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4)
        encoded += b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4)
        encoded += b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4)
        encoded += b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4)
        encoded += b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4)
        encoded += b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4)
        encoded += b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4)
        encoded += b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4)
        encoded += b64_from_24bit(0, alt_result[31], alt_result[30], 3)
        
        return f"{SALT_PREFIX}{salt}${encoded}"
    
    def _build_multipart_data(self, fields: Dict[str, str], 
                             attachments: List[Tuple[str, str, bytes]],
                             boundary: str) -> bytes:
        """
        Build multipart/form-data content.
        
        Args:
            fields: Dictionary of form fields
            attachments: List of (filename, field_name, data) tuples
            boundary: Multipart boundary string
            
        Returns:
            Complete multipart data as bytes
        """
        parts = []
        
        # Add form fields
        for name, value in fields.items():
            part = f"--{boundary}\r\n"
            part += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            part += f"{value}\r\n"
            parts.append(part.encode('utf-8'))
        
        # Add attachments
        for filename, field_name, data in attachments:
            part = f"--{boundary}\r\n"
            part += f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n\r\n'
            parts.append(part.encode('utf-8'))
            parts.append(data)
            parts.append(b"\r\n")
        
        # Add final boundary
        parts.append(f"--{boundary}--\r\n".encode('utf-8'))
        
        return b''.join(parts)
    
    def submit_entry(self, logbook: str, message: str, 
                    attributes: Optional[Dict[str, str]] = None,
                    attachments: Optional[Sequence[Tuple[str, Union[str, bytes, BinaryIO]]]] = None,
                    reply_to: Optional[int] = None,
                    edit_id: Optional[int] = None,
                    encoding: str = "plain",
                    suppress_email: bool = False) -> str:
        """
        Submit an entry to the ELOG server.
        
        Args:
            logbook: Name of the logbook/experiment
            message: The message text
            attributes: Dictionary of attribute name-value pairs
            attachments: List of (filename, file_data) tuples where file_data can be:
                        - str: file path to read from
                        - bytes: raw file data
                        - BinaryIO: file-like object
            reply_to: ID of message to reply to
            edit_id: ID of message to edit
            encoding: Message encoding ("plain", "HTML", "ELCode")
            suppress_email: Whether to suppress email notification
            
        Returns:
            Server response
            
        Raises:
            ElogSubmissionError: If submission fails
        """
        if attributes is None:
            attributes = {}
        if attachments is None:
            attachments = []
            
        sock = self._connect()
        
        try:
            # Generate boundary for multipart data
            boundary = self._generate_boundary()
            
            # Build form fields
            fields = {
                "cmd": "Submit",
                "exp": logbook,
                "Text": message,
                "encoding": encoding
            }
            
            # Add authentication if provided
            if self.username:
                fields["unm"] = self.username
            if self.password:
                fields["upwd"] = self._encrypt_password(self.password)
            
            # Add optional fields
            if reply_to:
                fields["reply_to"] = str(reply_to)
            if edit_id:
                fields["edit_id"] = str(edit_id)
                fields["skiplock"] = "1"
            if suppress_email:
                fields["suppress"] = "1"
            
            # Add attributes
            for attr_name, attr_value in attributes.items():
                # Convert attribute name to lowercase
                fields[attr_name.lower()] = attr_value
            
            # Process attachments
            attachment_data = []
            for i, (filename, file_data) in enumerate(attachments):
                if isinstance(file_data, str):
                    # File path
                    with open(file_data, 'rb') as f:
                        data = f.read()
                elif isinstance(file_data, bytes):
                    # Raw bytes
                    data = file_data
                elif isinstance(file_data, (bytearray, memoryview)):
                    # Convert to bytes
                    data = bytes(file_data)
                elif hasattr(file_data, 'read'):
                    # File-like object
                    data = file_data.read()
                    if not isinstance(data, bytes):
                        data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
                else:
                    raise ValueError(f"Unsupported file_data type: {type(file_data)}")
                
                attachment_data.append((filename, f"attfile{i+1}", data))
            
            # Build multipart content
            content = self._build_multipart_data(fields, attachment_data, boundary)
            
            # Build HTTP request
            path = "/"
            if self.subdir:
                path += f"{self.subdir}/"
            if logbook:
                encoded_logbook = self._url_encode(logbook)
                path += f"{encoded_logbook}/"
            
            request = f"POST {path} HTTP/1.0\r\n"
            request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            request += f"Host: {self.hostname}"
            if self.port != 80:
                request += f":{self.port}"
            request += "\r\n"
            request += "User-Agent: PyElog\r\n"
            request += f"Content-Length: {len(content)}\r\n"
            request += "\r\n"
            
            # Send request and content
            self._send_request(sock, request)
            self._send_data(sock, content)
            
            # Receive response
            response = self._receive_response(sock)
            
            # Check for errors in response
            if "Error:" in response or "HTTP/1.0 40" in response or "HTTP/1.0 50" in response:
                raise ElogSubmissionError(f"Server error: {response}")
            
            return response
            
        finally:
            sock.close()
    
    def retrieve_entry(self, logbook: str, message_id: int) -> Tuple[Dict[str, str], str]:
        """
        Retrieve an entry from the ELOG server.
        
        Args:
            logbook: Name of the logbook/experiment
            message_id: ID of the message to retrieve
            
        Returns:
            Tuple of (attributes_dict, message_text)
            
        Raises:
            ElogRetrievalError: If retrieval fails
        """
        sock = self._connect()
        
        try:
            # Build request path
            path = "/"
            if self.subdir:
                path += f"{self.subdir}/"
            if logbook:
                encoded_logbook = self._url_encode(logbook)
                path += f"{encoded_logbook}/"
            path += f"{message_id}?cmd=download"
            
            # Build HTTP request
            request = f"GET {path} HTTP/1.0\r\n"
            request += "User-Agent: PyElog\r\n"
            
            # Add authentication cookies if provided
            cookies = []
            if self.username:
                cookies.append(f"unm={self.username}")
            if self.password:
                encrypted_pwd = self._encrypt_password(self.password)
                cookies.append(f"upwd={encrypted_pwd}")
            
            if cookies:
                request += f"Cookie: {';'.join(cookies)}\r\n"
            
            request += "\r\n"
            
            # Send request
            self._send_request(sock, request)
            
            # Receive response
            response = self._receive_response(sock)
            
            # Check for errors
            if "Error:" in response or "HTTP/1.0 40" in response or "HTTP/1.0 50" in response:
                raise ElogRetrievalError(f"Server error: {response}")
            
            # Parse response
            if "$@MID@$:" not in response:
                raise ElogRetrievalError("Invalid response format")
            
            return self._parse_entry_response(response)
            
        finally:
            sock.close()
    
    def _parse_entry_response(self, response: str) -> Tuple[Dict[str, str], str]:
        """
        Parse the response from an entry retrieval.
        
        Args:
            response: Raw HTTP response
            
        Returns:
            Tuple of (attributes_dict, message_text)
        """
        # Find the start of the entry data
        mid_marker = "$@MID@$:"
        if mid_marker not in response:
            raise ElogRetrievalError("Response does not contain entry data")
        
        # Extract entry content
        entry_start = response.find(mid_marker)
        entry_content = response[entry_start:]
        
        # Find the separator between attributes and message
        separator = "========================================\n"
        if separator not in entry_content:
            # Try alternative separator
            separator = "=" * 40 + "\n"
            if separator not in entry_content:
                raise ElogRetrievalError("Cannot find attribute/message separator")
        
        attr_section, message_text = entry_content.split(separator, 1)
        
        # Parse attributes
        attributes = {}
        lines = attr_section.split('\n')
        
        # Skip the MID line
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                attributes[key.strip()] = value.strip()
        
        return attributes, message_text.strip()
    
    def list_entries(self, logbook: str, limit: Optional[int] = None) -> List[Dict[str, str]]:
        """
        List entries in a logbook (simplified implementation).
        
        Args:
            logbook: Name of the logbook/experiment
            limit: Maximum number of entries to return
            
        Returns:
            List of entry information dictionaries
            
        Note:
            This is a simplified implementation. The actual ELOG protocol
            for listing entries is more complex and may require parsing HTML.
        """
        # This would require implementing the HTML parsing logic
        # from the ELOG web interface, which is quite complex
        raise NotImplementedError("Entry listing not yet implemented")


# Convenience functions
def submit_entry(hostname: str, logbook: str, message: str,
                port: int = 80, use_ssl: bool = False,
                username: str = "", password: str = "",
                attributes: Optional[Dict[str, str]] = None,
                attachments: Optional[List[Tuple[str, Union[str, bytes, BinaryIO]]]] = None,
                **kwargs) -> str:
    """
    Convenience function to submit a single entry.
    
    Args:
        hostname: ELOG server hostname
        logbook: Logbook name
        message: Message text
        port: Server port
        use_ssl: Whether to use SSL
        username: Username for authentication
        password: Password for authentication
        attributes: Entry attributes
        attachments: File attachments
        **kwargs: Additional arguments for submit_entry
        
    Returns:
        Server response
    """
    client = ElogClient(hostname, port, use_ssl, username=username, password=password)
    return client.submit_entry(logbook, message, attributes, attachments, **kwargs)


def retrieve_entry(hostname: str, logbook: str, message_id: int,
                  port: int = 80, use_ssl: bool = False,
                  username: str = "", password: str = "") -> Tuple[Dict[str, str], str]:
    """
    Convenience function to retrieve a single entry.
    
    Args:
        hostname: ELOG server hostname
        logbook: Logbook name
        message_id: ID of message to retrieve
        port: Server port
        use_ssl: Whether to use SSL
        username: Username for authentication
        password: Password for authentication
        
    Returns:
        Tuple of (attributes_dict, message_text)
    """
    client = ElogClient(hostname, port, use_ssl, username=username, password=password)
    return client.retrieve_entry(logbook, message_id)


# Example usage
if __name__ == "__main__":
    # Example: Submit an entry
    try:
        client = ElogClient("localhost", 8080, False, username="admin", password="admin")
        
        response = client.submit_entry(
            logbook="demo",
            message="Test message from PyElog",
            attributes={
                "Author": "PyElog User",
                "Type": "Routine",
                "Subject": "Test Entry"
            }
        )
        print("Entry submitted successfully!")
        print(response)
        
    except ElogError as e:
        print(f"ELOG Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")