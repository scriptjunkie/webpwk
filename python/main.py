#!/usr/bin/env python3
"""webpwk - web password based keying - example server

Defends against exposed secrets (passwords) in use or in transit like how hashing defends
against exposing passwords at rest.

Instead of sending the password directly, the client first derives an asymmetric key pair
from the password using a key derivation function (KDF). The client then sends a request to
/challenge, and the server replies with a challenge. The client then signs the challenge with
its private key and sends the signature back to the server. The server then verifies the
signature with the public key. If the signature is invalid, the server returns an error message.

If the signature is valid, the server continues with the normal logon or registration process,
treating the public key as the password.

This example server is a simple HTTP server that implements the above protocol. Data is stored
in the filesystem for simplicity. Challenges are stored in memory and removed after use.
/register checks to see if the name has already been registered and if not, creates a
new folder whose name is the hex encoding of the provided username. Inside the folder, it stores a file
called "salt" containing a random salt, and a file called "hmac" containing the HMAC of the
public key and salt.
"""

import os
import hmac
import hashlib
import secrets
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Challenges for this demonstration are stored in a set
challenges = set()


def remove_challenge_after_timeout(challenge, timeout=10):
    """Remove a challenge after a timeout period"""
    time.sleep(timeout)
    challenges.discard(challenge)


class WebPWKHandler(BaseHTTPRequestHandler):
    error_message_format = '%(message)s'
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"handling request {self.path}")
    
    def send_cors_headers(self):
        """Send CORS headers for browser compatibility"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, name')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
    
    def do_OPTIONS(self):
        """Handle preflight requests"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        # Step 1: client requests challenge, server generates random 32 byte challenge and returns it
        if self.path == '/challenge':
            challenge = secrets.token_bytes(32)
            challenges.add(challenge)
            # Remove the challenge after 10 seconds so it times out
            threading.Thread(target=remove_challenge_after_timeout, args=(challenge,), daemon=True).start()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(challenge)
            return
        
        # Serve login.html for root and /index.html
        if self.path == '/' or self.path == '/index.html':
            login_html_path = Path(__file__).parent.parent / 'login.html'
            try:
                with open(login_html_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_error(404, "login.html not found")
            return
        
        # 404 for everything else
        self.send_error(404)
    
    def do_POST(self):
        """Handle POST requests for /register and /login"""
        # Step 2: client sends public key, challenge, and signature, server validates crypto
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length != 32 + 64 + 32:  # pubkey + signature + challenge
                self.send_error(400, "Failed to read body")
                return
            
            buf = self.rfile.read(content_length)
            pubkey = buf[:32]
            signature = buf[32:32+64]
            challenge = buf[32+64:32+64+32]
            
            # Verify the signature
            try:
                verify_key = VerifyKey(pubkey)
                verify_key.verify(challenge, signature)
            except (BadSignatureError, Exception):
                self.send_error(401, "Bad signature!")
                return
            
            # Step 3: See if challenge exists and delete it if so
            if challenge not in challenges:
                self.send_error(401, "Challenge not found")
                return
            challenges.remove(challenge)
            
            # Step 4: Continue like a normal logon or registration treating pubkey as the password
            name = self.headers.get('name', '')
            if not name or len(name) >= 64:
                self.send_error(400, "Missing or bad name")
                return
            
            namehex = name.encode().hex()
            
            # Registration - create new user
            if self.path == '/register':
                if os.path.exists(namehex):
                    self.send_error(400, "User already registered")
                    return
                
                salt = secrets.token_bytes(32)
                hmac_obj = hmac.new(pubkey, salt, hashlib.sha256)
                hmac_bytes = hmac_obj.digest()
                
                try:
                    os.makedirs(namehex, exist_ok=False)
                    with open(f"{namehex}/salt", 'wb') as f:
                        f.write(salt)
                    with open(f"{namehex}/hmac", 'wb') as f:
                        f.write(hmac_bytes)
                except Exception as e:
                    # On error, try to undo everything
                    try:
                        import shutil
                        shutil.rmtree(namehex, ignore_errors=True)
                    except:
                        pass
                    self.send_error(500, "Failed to write files")
                    return
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"Registration complete")
            
            # Login - verify user
            elif self.path == '/login':
                if not os.path.exists(namehex):
                    self.send_error(401, "User not registered")
                    return
                
                try:
                    with open(f"{namehex}/salt", 'rb') as f:
                        salt = f.read()
                    with open(f"{namehex}/hmac", 'rb') as f:
                        stored_hmac = f.read()
                    
                    # The client is already verified to own the key, now verify the key is for this user
                    hmac_obj = hmac.new(pubkey, salt, hashlib.sha256)
                    computed_hmac = hmac_obj.digest()
                    
                    if not hmac.compare_digest(computed_hmac, stored_hmac):
                        self.send_error(401, "Invalid credentials")
                        return
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_cors_headers()
                    self.end_headers()
                    self.wfile.write(f"Login successful for {name}".encode())
                except Exception:
                    self.send_error(500, "Failed to read files")
            else:
                self.send_error(404)
        
        except Exception as e:
            print(f"Error processing request: {e}")
            self.send_error(500, "Internal server error")


def main():
    server_address = ('127.0.0.1', 2203)
    httpd = HTTPServer(server_address, WebPWKHandler)
    print(f"Starting webpwk server on {server_address[0]}:{server_address[1]}")
    httpd.serve_forever()


if __name__ == '__main__':
    main()
