import os
import hashlib
import re
import argparse

# --- CRITICAL INDICATORS FROM DISCLOSURE ---

# Trial Experiment IDs (UUIDs) identified in Attribution Report
# Reference: EXTERNAL_CONTROL_PLANE_AND_ATTRIBUTION_REPORT.md
TARGET_UUIDS = [
    "049879DA-AFA2-3BA3-B017-62A011758A11",
    "068608DE-FF2B-3B42-B9E2-1790F49D7F1F",
    "0802608C-E262-3681-B4B2-2C3C69335E5A",
    "0DC723BF-4338-355F-AAA4-3B3DB3E37FF2",
    "101940A3-1A17-3070-B11A-25D585B1BC44"
]

# Known Security Policy Exception Strings
# Reference: DATA_PROTECTION_POLICY_BYPASS_AUDIT.md
EXCEPTION_STRINGS = [
    "5com.apple.dataprotection.policy.exception-applied-by",
    "com.apple.mobileassetd",
    "com.apple.wifivelocityd"
]

# Integrity Hashes for Key Forensic Artifacts
# Reference: FORENSIC_MANIFEST_AND_INTEGRITY_INDEX.csv
INTEGRITY_MANIFEST = {
    "DSCSYM-101940A3-1A17-3070-B11A-25D585B1BC44": "37cb3b8a60fc76a4978dc751e4ecdefd735261b4c9d25d228f41806d25be5c8b",
    "._tailspin-info.txt": "d77e265e4e35c81d17761bfbc47c7fae3d45141b55fe63a407e4bf92d69ffbb3"
}

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_directory(directory_path):
    print(f"[*] Commencing forensic scan of: {directory_path}")
    matches = {"uuids": [], "exceptions": [], "hashes": []}

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            # 1. Check for Integrity Hash matches
            if file in INTEGRITY_MANIFEST:
                current_hash = calculate_sha256(file_path)
                if current_hash == INTEGRITY_MANIFEST[file]:
                    matches["hashes"].append(f"MATCH: {file} (Hash: {current_hash})")

            # 2. Scan file content for UUIDs and Exceptions
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    for uuid in TARGET_UUIDS:
                        if uuid in content:
                            matches["uuids"].append(f"FOUND: {uuid} in {file}")
                    
                    for exc in EXCEPTION_STRINGS:
                        if exc in content:
                            matches["exceptions"].append(f"FLAGGED: Policy Exception ({exc}) in {file}")
            except Exception:
                continue

    return matches

def report_findings(matches):
    print("\n--- FORENSIC VERIFICATION REPORT ---")
    
    if not any(matches.values()):
        print("[+] No indicators from Project Stepped-On Silicon detected.")
        return

    if matches["hashes"]:
        print("\n[!] CRITICAL: IDENTICAL EXPLOIT ARTIFACTS DETECTED")
        for m in matches["hashes"]: print(f"  - {m}")

    if matches["uuids"]:
        print("\n[!] ATTRIBUTION: KNOWN CONTROL PLANE EXPERIMENTS DETECTED")
        for m in matches["uuids"]: print(f"  - {m}")

    if matches["exceptions"]:
        print("\n[!] AUDIT: UNAUTHORIZED SECURITY EXCEPTIONS DETECTED")
        for m in matches["exceptions"]: print(f"  - {m}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify Project Stepped-On Silicon Indicators")
    parser.get_argument("path", help="Path to the extracted sysdiagnose directory")
    args = parser.parse_args()
    
    findings = scan_directory(args.path)
    report_findings(findings)
