# Full Disclosure: Project Stepped-On Silicon

### Forensic Verification of Silicon-Level Persistence

## Overview

This repository contains a coordinated forensic disclosure regarding the discovery of an unauthorized, hardware-persistent control plane identified on an **iPhone 14 Pro Max (D74AP)** running **iOS 26.2.1 (Build 23C71)**.

The evidence provided proves the existence of **Data Protection Policy Bypasses** and **Silent Provisioning** mechanisms that survive a full DFU (Device Firmware Upgrade) restore. This research is being released to the public and the security industry to enable peer review and cross-device verification of these systemic vulnerabilities.

---

## Technical Evidence Set

The disclosure is organized into five core forensic artifacts derived from a 10GB system-level dump:

1. **`EXECUTIVE_TRIAGE_AND_HARDWARE_VERIFICATION.md`**: The primary narrative and triage report. It documents critical hardware identifiers (D74AP) and system state logs that anchor the evidence to a specific physical device.
2. **`DATA_PROTECTION_POLICY_BYPASS_AUDIT.md`**: A comprehensive audit of system-level metadata proving that privileged daemons—including `mobileassetd`, `wifivelocityd`, and `ManagedSettingsAgent`—are granted explicit exceptions to standard iOS Data Protection policies.
3. **`EXTERNAL_CONTROL_PLANE_AND_ATTRIBUTION_REPORT.md`**: A catalog of **Trial Experiment IDs (UUIDs)** and network telemetry indicators. These IDs serve as cryptographic markers for the remote, silent reconfiguration of device parameters.
4. **`FORENSIC_MANIFEST_AND_INTEGRITY_INDEX.csv`**: The master inventory of the 10GB forensic corpus. Every file is indexed with a **SHA-256 hash** to ensure the integrity of the evidence and allow researchers to check for matching artifacts on other devices.
5. **`VERIFY_INDICATORS.py`**: An automated diagnostic script designed to scan local `sysdiagnose` captures for the Trial UUIDs and Policy Exceptions documented in this repository.

---

## Core Findings

### 1. Persistent System Bypasses

The **Security Policy Audit** reveals that `com.apple.mobileassetd` has been granted a `dataprotection.policy.exception` to manage filesystem and locker histories. This framework allows for the silent injection of system assets that reside in non-volatile storage regions, effectively bypassing the "security wipe" typically associated with a DFU restore.

### 2. Unauthorized Control Plane (Trial Framework)

The **Attribution Report** identifies dozens of active **Trial Experiment IDs** (e.g., `101940A3-1A17-3070-B11A-25D585B1BC44`) embedded within diagnostic symbols. These IDs identify a hidden layer of management that operates outside of user-facing settings.

### 3. Diagnostic Exfiltration Vector

The audit documents an exhaustive list of exceptions for **`com.apple.wifivelocityd`**, granting it access to network telemetry, interface configurations, and Wi-Fi state data. This confirms a documented path for the exfiltration of sensitive network artifacts under the guise of system diagnostics.

---

## Active Verification Toolkit

Researchers can use the included **`VERIFY_INDICATORS.py`** script to audit their own devices for the indicators found in this disclosure.

### Usage

1. Generate a `sysdiagnose` on your iPhone and extract the results.
2. Execute the verification script against the extracted directory:
```bash
python VERIFY_INDICATORS.py /path/to/sysdiagnose_directory

```


3. The script will automatically scan for matching **Trial UUIDs**, unauthorized **Policy Exceptions**, and verify file integrity against the **Forensic Manifest**.

---

## Data Integrity and Reproducibility

The **`FORENSIC_MANIFEST_AND_INTEGRITY_INDEX.csv`** provides a verifiable "Golden Image" of the system state. By comparing local file hashes against this manifest, researchers can prove the existence of identical exploit artifacts or unauthorized system configurations across different hardware.

---
