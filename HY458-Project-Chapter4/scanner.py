import os
import sys
import sqlite3
import time
import re

RISK_LEVELS = {
    "SECURE": [
        r"ssh-keygen\s*-t\s*rsa\s*-b\s*(2048|4096)",
        r"openssl\s*genrsa\s*(2048|4096)",
        r"openssl\s*req\s*-new\s*-x509\s*-keyout\s*\S+\s*-out\s*\S+\s*-days\s*\d+\s*-newkey\s*rsa:(2048|4096)",
        r"HMAC\s*SHA-256",
        r"hmac\.new\(.*?,\s*hashlib\.sha256\)",
        r"hmac\.new\s*\(.*?,\s*.*?,\s*hashlib\.sha256\s*\)",
    ],
    "LOW": [
        r"hashlib\.sha256\(.*?\)",
        r"MessageDigest\s+getInstance\s*\(\s*\"SHA-256\"\s*\)",
        r"SHA-512(?!.*HMAC)",
        r"AES\s*\(\s*128\s*\)(?!.*CBC)",
        r"Cipher\.getInstance\(\"AES/128\"\)(?!.*CBC)",
        r"encrypt_aes128\((?!.*CBC)",
        r"decrypt_aes128\((?!.*CBC)",
        r"KeyGenerator\.getInstance\(\"AES\"\)",
        r"keyGen\.init\(128\)",
    ],
    "MEDIUM": [
        r"3DES",
        r"DES3",
        r"TripleDES",
        r"AES\s*\(\s*ECB\s*\)",
        r"RSA\s*\(\s*1536\s*\)",
    ],
    "HIGH": [
        r"MD5",
        r"SHA-1",
        r"DES",
        r"RSA\s*\(\s*1024\s*\)",
    ]
}

REPLACEMENT_MAP = {
    "MD5": "SHA-256",
    "hashlib.md5": "hashlib.sha256",
    "SHA-1": "SHA-256",
    "hashlib.sha1": "hashlib.sha256",
    "DES": "AES-256",
    "DES.new": "AES.new",
    "3DES": "AES-192",
    "TripleDES": "AES-192",
    "RSA-1024": "RSA-4096",
    r"AES\(ECB\)": "AES-256 (GCM)",
    r"RSA\(1536\)": "RSA-4096 or ECC-P384",
    r"AES\(128\)": "AES-256",
}


def initialize_database():
    if os.path.exists("crypto_scan_results.db"):
        os.remove("crypto_scan_results.db")

    conn = sqlite3.connect("crypto_scan_results.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        language TEXT,
        line_number INTEGER,
        vulnerable_code TEXT,
        fixed_code TEXT DEFAULT NULL,
        risk_level TEXT,
        new_risk_level TEXT DEFAULT NULL
    )
    """)
    conn.close()


def detect_language(file_path):
    _, ext = os.path.splitext(file_path)
    return {
        '.py': 'Python',
        '.java': 'Java',
        '.c': 'C',
    }.get(ext.lower(), 'Unknown')


def analyze_file(file_path):
    results = {"HIGH": [], "MEDIUM": [], "LOW": [], "SECURE": []}
    replacements = {}

    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    for i, line in enumerate(lines, start=1):
        for risk, patterns in RISK_LEVELS.items():
            for pattern in patterns:
                if re.search(pattern, line):
                    fixed_line = line
                    for weak_alg, strong_alg in REPLACEMENT_MAP.items():
                        if re.search(weak_alg, line):
                            fixed_line = re.sub(weak_alg, strong_alg, line)
                            replacements[line.strip()] = fixed_line.strip()
                            break
                    results[risk].append((i, line.strip()))

    save_results_to_db(file_path, results, detect_language(file_path), replacements)


def save_results_to_db(file_path, results, language, replacements):
    conn = sqlite3.connect("crypto_scan_results.db")
    cursor = conn.cursor()
    filename = os.path.basename(file_path)

    for risk, findings in results.items():
        for line_num, original_code in findings:
            fixed_code = replacements.get(original_code, "Manual Review Needed")
            new_risk_level = "SECURE" if fixed_code != "Manual Review Needed" else risk
            cursor.execute("""
                INSERT INTO findings (filename, language, line_number, vulnerable_code, fixed_code, risk_level, new_risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (filename, language, line_num, original_code, fixed_code, risk, new_risk_level))
    conn.commit()
    conn.close()


def scan_folder(folder_path):
    if not os.path.exists(folder_path):
        print("[ERROR] Folder does not exist.")
        return

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            analyze_file(file_path)


if __name__ == "__main__":
    initialize_database()
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <folder-to-scan>")
        sys.exit(1)
    scan_folder(sys.argv[1])
