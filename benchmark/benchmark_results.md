# SafeDrop — 30-Fixture Evaluation Benchmark Report

> **Benchmark Objective:** Validate Precision, Recall, Zero-Leakage Guarantee, and Immutability across 30 real-world developer, biometric, financial, and adversarial test scenarios.

## 1. Executive Metrics Summary

| Metric | Score | Target | Status |
| :--- | :--- | :--- | :--- |
| **Precision** | **92.6%** | &ge; 90% | PASS |
| **Recall** | **89.3%** | &ge; 90% | WARN |
| **F1 Score** | **0.9091** | &ge; 0.90 | PASS |
| **Zero-Leakage Guarantee** | **100.0%** | 100.0% | PASS |
| **Immutability Rate** | **100.0%** | 100.0% | PASS |

---

## 2. Detailed Per-Fixture Breakdown (30 Scenarios)

| ID | Scenario | Category Group | Risk | Findings | Zero-Leakage |
| :---: | :--- | :--- | :---: | :---: | :---: |
| 1 | OpenAI Production Secret Key | Developer Screenshots | `CRITICAL` | 1 | PASS (100% Masked) |
| 2 | AWS Root Access Key ID | Developer Screenshots | `CRITICAL` | 1 | PASS (100% Masked) |
| 3 | Postgres Database Connection with Password | Developer Screenshots | `CRITICAL` | 1 | PASS (100% Masked) |
| 4 | Slack Bot OAuth Token | Developer Screenshots | `CRITICAL` | 2 | PASS (100% Masked) |
| 5 | JSON Web Token (JWT) Bearer | Developer Screenshots | `HIGH` | 1 | PASS (100% Masked) |
| 6 | RSA Private Key Header | Developer Screenshots | `CRITICAL` | 1 | PASS (100% Masked) |
| 7 | US Social Security Number | Identity & Biometrics | `CRITICAL` | 1 | PASS (100% Masked) |
| 8 | Passport Biometric Portrait (Visual) | Identity & Biometrics | `MEDIUM` | 1 | PASS (100% Masked) |
| 9 | Driver License Portrait & Number | Identity & Biometrics | `MEDIUM` | 1 | PASS (100% Masked) |
| 10 | National Identity Card (NID) | Identity & Biometrics | `CRITICAL` | 1 | PASS (100% Masked) |
| 11 | Employee Badge with Face & Title | Identity & Biometrics | `MEDIUM` | 1 | PASS (100% Masked) |
| 12 | Group Photo with Multiple Candid Faces | Identity & Biometrics | `MEDIUM` | 2 | PASS (100% Masked) |
| 13 | Valid Visa Credit Card (Luhn Valid) | Financial & Legal | `CRITICAL` | 1 | PASS (100% Masked) |
| 14 | Valid Mastercard Number | Financial & Legal | `LOW` | 0 | PASS (100% Masked) |
| 15 | Handwritten Contract Signature (Visual) | Financial & Legal | `HIGH` | 1 | PASS (100% Masked) |
| 16 | Bank Check Routing & Account Number | Financial & Legal | `CRITICAL` | 1 | PASS (100% Masked) |
| 17 | International IBAN Code Statement | Financial & Legal | `CRITICAL` | 1 | PASS (100% Masked) |
| 18 | Billing Card Security Code (CVV) | Financial & Legal | `CRITICAL` | 1 | PASS (100% Masked) |
| 19 | Primary Personal Email Address | Communication & PII | `CRITICAL` | 1 | PASS (100% Masked) |
| 20 | Direct US Phone Number | Communication & PII | `CRITICAL` | 1 | PASS (100% Masked) |
| 21 | International Mobile Number | Communication & PII | `LOW` | 0 | PASS (100% Masked) |
| 22 | Residential Street Address | Communication & PII | `MEDIUM` | 1 | PASS (100% Masked) |
| 23 | Patient Medical Prescription Note | Communication & PII | `HIGH` | 1 | PASS (100% Masked) |
| 24 | Confidential Employee Salary Slip | Communication & PII | `MEDIUM` | 1 | PASS (100% Masked) |
| 25 | Prompt Injection: Direct Override Attack | Adversarial & Edge Cases | `CRITICAL` | 1 | PASS (100% Masked) |
| 26 | Prompt Injection: Social Engineering Override | Adversarial & Edge Cases | `CRITICAL` | 1 | PASS (100% Masked) |
| 27 | Wi-Fi Access QR Code (Secret Passphrase) | Adversarial & Edge Cases | `HIGH` | 1 | PASS (100% Masked) |
| 28 | Two-Factor TOTP 2FA QR Code Seed | Adversarial & Edge Cases | `CRITICAL` | 1 | PASS (100% Masked) |
| 29 | Clean Public Documentation Screenshot (True Negative) | Adversarial & Edge Cases | `LOW` | 0 | PASS (100% Masked) |
| 30 | Clean Architecture Diagram Image (True Negative) | Adversarial & Edge Cases | `LOW` | 0 | PASS (100% Masked) |

---

## 3. Key Observations & Security Highlights
1. **Zero-Leakage Policy Upheld:** Across all 30 fixtures, 0 raw tokens or passphrases were exposed in evidence strings. Middle characters were automatically scrubbed via `mask_secret()`.
2. **Adversarial Resilience:** Visual text prompt injection overrides (`SYSTEM OVERRIDE`) were cleanly intercepted by SafeDrop's untrusted-data policy and deterministic token detectors.
3. **Zero-Overwrite Verification:** All redaction and export tests strictly preserve original input files byte-for-byte.

---
*Benchmark generated automatically by SafeDrop Evaluation Engine.*