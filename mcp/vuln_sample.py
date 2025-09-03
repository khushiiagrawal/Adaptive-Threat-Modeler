import os
import subprocess
import sqlite3
import hashlib
import yaml
import pickle
import requests
from flask import Flask, request


# Hardcoded secret (vulnerability: hardcoded credential)
API_KEY = "sk_live_1234567890SECRET"


def run_system_command(user_input: str) -> str:
    """VULN: Command injection via shell=True and unsanitized input."""
    try:
        out = subprocess.check_output(user_input, shell=True)
        return out.decode("utf-8", errors="ignore")
    except Exception as exc:
        return f"error: {exc}"


def query_user_by_name(db_path: str, user_name: str):
    """VULN: SQL injection via string formatting instead of parameters."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    sql = f"SELECT id, name, email FROM users WHERE name = '{user_name}'"  # nosec
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows


def evaluate_expression(expr: str):
    """VULN: Arbitrary code execution via eval."""
    return eval(expr)  # nosec


def parse_yaml_untrusted(yaml_str: str):
    """VULN: Unsafe YAML load allowing arbitrary object construction."""
    return yaml.load(yaml_str)  # nosec


def deserialize_untrusted(data: bytes):
    """VULN: Unsafe deserialization with pickle.loads."""
    return pickle.loads(data)  # nosec


def weak_password_hash(password: str) -> str:
    """VULN: Weak hashing algorithm (MD5)."""
    return hashlib.md5(password.encode()).hexdigest()  # nosec


def download_insecure(url: str) -> str:
    """VULN: TLS verification disabled."""
    r = requests.get(url, verify=False)  # nosec
    return r.text


def save_upload(filename: str, content: bytes):
    """VULN: Path traversal by concatenating user-controlled filename."""
    upload_path = os.path.join("uploads", filename)
    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
    with open(upload_path, "wb") as f:
        f.write(content)
    return upload_path


# Minimal Flask app with debug enabled (information disclosure)
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"  # VULN: hardcoded secret


@app.route("/run", methods=["POST"])
def run():
    cmd = request.form.get("cmd", "echo hello")
    return run_system_command(cmd)


@app.route("/calc", methods=["POST"])
def calc():
    expr = request.form.get("expr", "1+1")
    return str(evaluate_expression(expr))


if __name__ == "__main__":
    # VULN: debug=True should not be used in production
    app.run(host="0.0.0.0", port=5001, debug=True)


