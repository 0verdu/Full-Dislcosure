import os
import hashlib
import csv
import argparse
from datetime import datetime

# --- CRITICAL INDICATORS FROM DISCLOSURE ---

# Trial Experiment IDs (UUIDs) identified in Attribution Report
TARGET_UUIDS = [
    "049879DA-AFA2-3BA3-B017-62A011758A11",
    "068608DE-FF2B-3B42-B9E2-1790F49D7F1F",
    "0802608C-E262-3681-B4B2-2C3C69335E5A",
    "0DC723BF-4338-355F-AAA4-3B3DB3E37FF2",
    "101940A3-1A17-3070-B11A-25D585B1BC44",
    "69C4C4BB-B5A4-5F59-8CDE-680F95FE76F1"
]

# Known Security Policy Exception Strings
EXCEPTION_STRINGS = [
    "5com.apple.dataprotection.policy.exception-applied-by",
    "com.apple.mobileassetd",
    "com.apple.wifivelocityd"
]

# Exfiltration Domain
EXFIL_DOMAIN = "kaylees.site"

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def load_manifest(csv_path):
    """Parses the Forensic Manifest CSV into a dictionary for lookup."""
    manifest = {}
    if not csv_path:
        return manifest
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                manifest[row['filename']] = row['sha256'].strip().lower()
        return manifest
    except Exception as e:
        print(f"[-] Error loading manifest: {e}")
        return {}

def run_audit(directory_path, manifest_path=None):
    print(f"[*] Commencing forensic audit of: {directory_path}")
    manifest = load_manifest(manifest_path)
    findings = {"uuids": [], "exceptions": [], "hashes": [], "network": []}
    scanned_count = 0

    for root, _, files in os.walk(directory_path):
        for file in files:
            scanned_count += 1
            file_path = os.path.join(root, file)
            
            # 1. Integrity Check via Manifest
            if file in manifest:
                if calculate_sha256(file_path) == manifest[file]:
                    findings["hashes"].append(f"MATCH: {file}")

            # 2. Content Scan
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    if EXFIL_DOMAIN in content:
                        findings["network"].append(f"EXFIL_TRAP: {EXFIL_DOMAIN} in {file}")

                    for uuid in TARGET_UUIDS:
                        if uuid in content:
                            findings["uuids"].append(f"FOUND: {uuid} in {file}")
                    
                    for exc in EXCEPTION_STRINGS:
                        if exc in content:
                            findings["exceptions"].append(f"FLAGGED: Policy Exception ({exc}) in {file}")
            except: continue

    return findings, scanned_count

def report_findings(findings, count):
    print("\n" + "="*60)
    print(" PROJECT STEPPED-ON SILICON: FORENSIC VERIFICATION REPORT")
    print("="*60)
    print(f"Files Scanned: {count}")

    if not any(findings.values()):
        print("\n[+] No indicators from Project Stepped-On Silicon detected.")
    else:
        if findings["hashes"]:
            print("\n[!] CRITICAL: IDENTICAL EXPLOIT ARTIFACTS DETECTED")
            for m in sorted(set(findings["hashes"])): print(f"  - {m}")

        if findings["network"]:
            print("\n[!] EXFILTRATION: KNOWN TUNNEL DOMAINS DETECTED")
            for m in sorted(set(findings["network"])): print(f"  - {m}")

        if findings["uuids"]:
            print("\n[!] ATTRIBUTION: CONTROL PLANE EXPERIMENTS DETECTED")
            for m in sorted(set(findings["uuids"])): print(f"  - {m}")

        if findings["exceptions"]:
            print("\n[!] AUDIT: UNAUTHORIZED SECURITY EXCEPTIONS DETECTED")
            for m in sorted(set(findings["exceptions"])): print(f"  - {m}")
    print("\n" + "="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify Project Stepped-On Silicon Indicators")
    parser.add_argument("path", help="Path to the extracted sysdiagnose directory")
    parser.add_argument("--manifest", help="Optional: Path to the CSV integrity manifest", default=None)
    args = parser.parse_args()
    
    findings, count = run_audit(args.path, args.manifest)
    report_findings(findings, count)
