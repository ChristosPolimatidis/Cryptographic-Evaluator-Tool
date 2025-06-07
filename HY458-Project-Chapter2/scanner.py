import re
import os
import sys
import sqlite3

RISK_LEVELS = {
    "SECURE": [
        r"ssh-keygen\s*-t\s*rsa\s*-b\s*(2048|4096)",  # SSH key generation
        r"openssl\s*genrsa\s*(2048|4096)",  # OpenSSL keygen
        r"openssl\s*req\s*-new\s*-x509\s*-keyout\s*\S+\s*-out\s*\S+\s*-days\s*\d+\s*-newkey\s*rsa:(2048|4096)",
        r"HMAC\s*SHA-256",  # Explicitly match HMAC-SHA-256
        r"hmac\.new\(.*?,\s*hashlib\.sha256\)",  # Detect Python HMAC-SHA-256 usage
        r"hmac\.new\s*\(.*?,\s*.*?,\s*hashlib\.sha256\s*\)",
    ],
    "LOW": [
        r"hashlib\.sha256\(.*?\)",  # Match Python hashlib SHA-256 usage
        r"MessageDigest\s+getInstance\s*\(\s*\"SHA-256\"\s*\)",  # Java SHA-256
        r"SHA-512(?!.*HMAC)",  # Standalone SHA-512
        r"AES\s*\(\s*128\s*\)(?!.*CBC)",
        r"AES\s*/\s*128(?!.*CBC)",
        r"Cipher\.getInstance\(\"AES/128\"\)(?!.*CBC)",
        r"encrypt_aes128\((?!.*CBC)",
        r"decrypt_aes128\((?!.*CBC)",
        r"KeyGenerator\.getInstance\(\"AES\"\)",
        r"keyGen\.init\(128\)",
        r"RSA\s*\(\s*(2048|4096)\s*\)",  # Direct function calls
        r"RSA_generate_key\s*\(\s*(2048|4096)\s*\)",  # C-style function
        r"KeyPairGenerator.getInstance\s*\(\s*\"RSA\"\s*\)\.initialize\s*\(\s*(2048|4096)\s*\)",  # Java
    ],
    "MEDIUM": [
        r"3DES",
        r"DES3",
        r"TripleDES",
        r"AES\s*\(\s*ECB\s*\)",
        r"RSA\s*\(\s*1536\s*\)",  # Somewhat weak RSA
    ],
    "HIGH": [
        r"MD5",
        r"SHA-1",
        r"DES",
        r"RSA\s*\(\s*1024\s*\)",  # Weak RSA (1024-bit)
        r"RSA\.generate\s*\(\s*1024\s*\)",
        r"RSA_generate_key\s*\(\s*1024\s*\)",  # C function
        r"KeyPairGenerator.getInstance\s*\(\s*\"RSA\"\s*\)\.initialize\s*\(\s*1024\s*\)",  # Java
        r"ssh-keygen\s*-t\s*rsa\s*-b\s*1024",  # SSH keygen
        r"\.initialize\s*\(\s*1024\s*\)",
        r"RSA_generate_key\s*\(\s*1024\s*,\s*\w+\s*,\s*NULL\s*,\s*NULL\s*\)",
        r"openssl\s*genrsa\s*1024",  # OpenSSL
        r"openssl\s*req\s*-new\s*-x509\s*-keyout\s*\S+\s*-out\s*\S+\s*-days\s*\d+\s*-newkey\s*rsa:1024"  # OpenSSL cert generation
    ]
}


def initialize_database():
    if os.path.exists("crypto_scan_results.db"):
        os.remove("crypto_scan_results.db")

    """Initialize the database with the findings table and clear old data."""
    conn = sqlite3.connect("crypto_scan_results.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        language TEXT,
        line_number INTEGER,
        vulnerable_code TEXT,
        risk_level TEXT
    )
    """)
    cursor.execute("DELETE FROM findings")  # Clear all old data
    conn.commit()
    conn.close()

def detect_language(file_path):
    """Detect the programming language based on file extension."""
    _, ext = os.path.splitext(file_path)
    languages = {
        '.py': 'Python',
        '.java': 'Java',
        '.js': 'JavaScript',
        '.cpp': 'C++',
        '.c': 'C',
        '.html': 'HTML',
        '.css': 'CSS',
        '.php': 'PHP',
        '.rb': 'Ruby',
    }
    return languages.get(ext.lower(), 'Unknown')

def save_results_to_db(file_path, results, language):
    """Save scan results to the database."""
    conn = sqlite3.connect("crypto_scan_results.db")
    cursor = conn.cursor()

    filename = os.path.basename(file_path)  # Extract only the filename

    for risk, findings in results.items():
        for line_num, code in findings:
            cursor.execute("""
            INSERT INTO findings (filename, language, line_number, vulnerable_code, risk_level)
            VALUES (?, ?, ?, ?, ?)
            """, (filename, language, line_num, code, risk))

    conn.commit()
    conn.close()

def analyze_file(file_path):
    results = {"HIGH": [], "MEDIUM": [], "LOW": [], "SECURE": []}
    has_vulnerabilities = False  # Track if vulnerabilities exist

    # Comment markers for different languages
    comment_markers = {
        "Python": r"^\s*#",          # Python-style comments
        "Java": r"^\s*//",           # Java single-line comments
        "C": r"^\s*//",              # C single-line comments
    }

    try:
        # Detect language for the current file
        language = detect_language(file_path)
        comment_pattern = comment_markers.get(language, None)

        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                # Ignore lines that match the comment pattern for the detected language
                if comment_pattern and re.match(comment_pattern, line):
                    continue

                # Ignore return statements that contain cryptographic functions
                if re.search(r"\breturn\b", line, re.IGNORECASE):
                    continue

                matched_risk = None
                for risk in ["HIGH", "MEDIUM", "LOW", "SECURE"]:  # Ensure proper assignment
                    for pattern in RISK_LEVELS[risk]:
                        if re.search(pattern, line, re.IGNORECASE):
                            has_vulnerabilities = True  # Mark that file has risks
                            matched_risk = risk
                if matched_risk:
                    results[matched_risk].append((i, line.strip()))

        # Ensure SECURE is assigned **only if no LOW/MEDIUM/HIGH risks exist**
        if has_vulnerabilities:
            results.pop("SECURE", None)  # Remove SECURE if any risk is found
        else:
            results["SECURE"].append((0, "No vulnerabilities detected"))

    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None
    return results


def scan_folder(folder_path):
    if not os.path.isdir(folder_path):
        print("Error: Provided path is not a folder.")
        return
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"\nScanning file: {file_path}")
            language = detect_language(file_path)  # Detect language
            scan_results = analyze_file(file_path)
            if scan_results:
                save_results_to_db(file_path, scan_results, language)

if __name__ == "__main__":
    initialize_database()

    if len(sys.argv) < 2:
        print("Usage: python scanner.py <folder-to-scan>")
        sys.exit(1)
    folder_to_scan = sys.argv[1]
    if not os.path.exists(folder_to_scan):
        print("Error: Folder does not exist.")
        sys.exit(1)
    print(f"Scanning {folder_to_scan} for cryptographic security risks...\n")
    scan_folder(folder_to_scan)
