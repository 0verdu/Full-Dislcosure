import os
import hashlib
import csv
import argparse
from datetime import datetime

# --- CRITICAL INDICATORS FROM DISCLOSURE ---

# Trial Experiment IDs (UUIDs) identified in Attribution Report
# Reference: EXTERNAL_CONTROL_PLANE_AND_ATTRIBUTION_REPORT.md
TARGET_UUIDS = [
    "049879DA-AFA2-3BA3-B017-62A011758A11",
    "068608DE-FF2B-3B42-B9E2-1790F49D7F1F",
    "0802608C-E262-3681-B4B2-2C3C69335E5A",
    "0DC723BF-4338-355F-AAA4-3B3DB3E37FF2",
    "101940A3-1A17-3070-B11A-25D585B1BC44",
    "69C4C4BB-B5A4-5F59-8CDE-680F95FE76F1",
    "C2CB8408-5FD2-4DC3-8E49-AAA691E4DD8E"
]

# Known Security Policy Exception Strings
# Reference: DATA_PROTECTION_POLICY_BYPASS_AUDIT.md
EXCEPTION_STRINGS = [
    "5com.apple.dataprotection.policy.exception-applied-by",
    "com.apple.mobileassetd",
    "com.apple.wifivelocityd"
]

# Network Exfiltration Indicators
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
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Expecting columns: 'file_path' and 'sha256_hash'
                filename = os.path.basename(row['file_path'])
                manifest[filename] = row['sha256_hash'].strip().lower()
        return manifest
    except Exception as e:
        print(f"[-] Error loading manifest: {e}")
        return None

def run_integrity_audit(dump_path, csv_path=None):
    """
    Main forensic verification function.
    Scans sysdiagnose directory for indicators of Project Stepped-On Silicon.
    """
    print(f"[*] INITIATING FORENSIC VERIFICATION")
    print(f"[*] Target Directory: {dump_path}")
    if csv_path:
        print(f"[*] Manifest Source: {csv_path}")
    print()

    # Load manifest if provided
    manifest = load_manifest(csv_path) if csv_path else None
    
    matches = {
        "uuids": [],
        "exceptions": [],
        "hashes": [],
        "network": []
    }
    total_files_scanned = 0

    for root, _, files in os.walk(dump_path):
        for file in files:
            total_files_scanned += 1
            f_path = os.path.join(root, file)
            
            # 1. CROSS-REFERENCE HASHES FROM CSV
            if manifest and file in manifest:
                current_hash = calculate_sha256(f_path)
                if current_hash and current_hash == manifest[file]:
                    matches["hashes"].append(f"INTEGRITY_MATCH: {file} (Verified against Manifest)")

            # 2. SIGNATURE OVERLAY (UUID, exceptions, network indicators)
            try:
                with open(f_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for network exfiltration domain
                    if EXFIL_DOMAIN in content:
                        matches["network"].append(f"NETWORK_EXFIL: {EXFIL_DOMAIN} detected in {file}")
                    
                    # Check for Trial UUIDs
                    for uuid in TARGET_UUIDS:
                        if uuid in content:
                            matches["uuids"].append(f"CONTROL_PLANE: {uuid} detected in {file}")
                    
                    # Check for policy exceptions
                    for exc in EXCEPTION_STRINGS:
                        if exc in content:
                            matches["exceptions"].append(f"POLICY_BYPASS: {exc} in {file}")
            except:
                continue

    # --- FINAL REPORT ---
    print("="*80)
    print(" PROJECT STEPPED-ON SILICON: FORENSIC VERIFICATION REPORT")
    print("="*80)
    print(f"Files Scanned: {total_files_scanned}")
    
    total_matches = len(matches["hashes"]) + len(matches["uuids"]) + len(matches["exceptions"]) + len(matches["network"])
    
    if total_matches == 0:
        print("\n[+] No indicators from Project Stepped-On Silicon detected.")
        print("    This device diverges from the D74AP baseline.")
    else:
        print(f"\n[!] CRITICAL: {total_matches} INDICATOR(S) DETECTED")
        
        if matches["hashes"]:
            print("\n[!] IDENTICAL EXPLOIT ARTIFACTS (Hash Match):")
            for m in sorted(set(matches["hashes"])):
                print(f"    - {m}")
        
        if matches["uuids"]:
            print("\n[!] TRIAL FRAMEWORK CONTROL PLANE DETECTED:")
            for m in sorted(set(matches["uuids"])):
                print(f"    - {m}")
        
        if matches["exceptions"]:
            print("\n[!] UNAUTHORIZED SECURITY POLICY BYPASSES:")
            for m in sorted(set(matches["exceptions"])):
                print(f"    - {m}")
        
        if matches["network"]:
            print("\n[!] NETWORK EXFILTRATION INDICATORS:")
            for m in sorted(set(matches["network"])):
                print(f"    - {m}")
    
    print("\n" + "="*80)
    print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify Project Stepped-On Silicon Indicators on iOS sysdiagnose",
        epilog="For deep integrity verification, use --manifest flag with FORENSIC_MANIFEST_AND_INTEGRITY_INDEX.csv"
    )
    parser.add_argument("dump", help="Path to the extracted sysdiagnose folder")
    parser.add_argument("--manifest", help="Path to FORENSIC_MANIFEST_AND_INTEGRITY_INDEX.csv (optional)", default=None)
    args = parser.parse_args()
    
    run_integrity_audit(args.dump, args.manifest)
