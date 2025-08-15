# CipherShift: Quantum-Resilient Messaging & 2FA Framework for Air-Gapped Shift Terminals

## Project Summary
CipherShift is a fully offline, CLI-based secure messaging system designed for highly sensitive, air-gapped environments such as **SOC/NOC and SCADA system**s respectively,
It addresses the need for secure communication of critical handover messages among **shift-based users on a shared, offline machine**, where traditional methods like 
TLS, cloud services, and email are impractical due to zero network access and insider threat models.**The project integrates post-quantum cryptographic standards
to ensure secure key management, forward secrecy, and user authentication without ever storing plaintext passwords or symmetric keys.**


## Problem Statement
In **air-gapped environments and on shared terminals**, a limited secure mechanism exists for handover messaging. Traditional communication methods are unsuitable because of the risk of key exposure, 
**lack of forward secrecy**, and the impracticality of online services in these zero-network settings. **CipherShift** provides a robust solution to this problem.

## Key Features & Objectives

1.**Offline, Quantum-Resilient Messaging:** The system uses **CRYSTALS-Kyber KEM (now ML-KEM post FIPS203, August 2024)** for post-quantum secure key encapsulation and **AES-256 GCM for message encryption**

2.**Robust Authentication:** Users authenticate with a username and a password that is hashed using **bcrypt**. The password is then used with **PBKDF2 to derive a key that decrypts a TOTP secret**

3.**Air-Gapped 2FA**: Two-factor authentication is implemented using the Aegis Authenticator app, ensuring that OTPs are generated and verified entirely offline without relying on online services like Twilio.

4.**Forward Secrecy**: Symmetric keys are **ephemeral and are destroyed after the message is send or read**, ensuring that even if a private key is compromised later, past session messages cannot be decrypted.

5.**Key Management**: **Symmetric AES keys are not stored**. Instead, **a Kyber KEM shared secret is derived and passed through HKDF to create a unique, per-message AES-256-GCM key.**

6.**Audit Trail**: The system includes a lightweight **audit trail** that tags messages with metadata like timestamps, sender, and receiver to ensure accountability

## The CipherShift Workflow:

**The key steps in the process are:**

**Registration:** Users register with a username, password, and phone number. The password is hashed using **bcrypt**, **Kyber keys are generated, and a TOTP secret is encrypted with AES-GCM.**

**Login:** A user logs in with their username and password. **The password is used to derive an AES key via PBKDF2, which then decrypts the TOTP secret.**

**Verification:** The decrypted secret is used to verify the user's OTP with PyOTP, ensuring secure, offline two-factor authentication.

**Send Message:** The sender retrieves the recipient's public key. Kyber encapsulation is used to generate a shared secret and a ciphertext. The shared secret is passed through HKDF to derive a unique AES-GCM key, which encrypts the message with a fresh nonce.

**View Inbox:** The recipient retrieves their messages. **They use their private Kyber key to perform decapsulation, recovering the shared secret from the ciphertext**. **The shared secret is used with HKDF to derive the correct AES-GCM key, which decrypts the message.**


# Architecture — Detailed message flow & key lifecycle

# Summary (high level)

* For **every message** the sender generates a **one-time Kyber shared secret** (via encapsulation against the recipient public key).
* That shared secret is run through **HKDF** → produces a **fresh AES-256-GCM key** for that message.
* A fresh **96-bit nonce** (12 bytes) is used per encrypt operation from os.urandom(12)
* The ciphertext + nonce + Kyber ciphertext + minimal metadata are stored in `messages.json`.
* Immediately **after sending**, the sender **deletes** the shared secret and the derived AES key from memory and disk - **so the sender cannot decrypt or tamper later**.
* The **receiver decapsulates the stored Kyber ciphertext when they log in (or when they choose to read) and derives the same AES key to decrypt**. After readout the symmetric key and shared secret are destroyed.

---

## Detailed sender flow (step-by-step)

1. Sender loads the **recipient public Kyber key** from the DB.
2. Sender runs **kyber.encapsulate(recipient_pub)** → yields:
   
 * kyber_ct (Kyber ciphertext)
 *  shared_secret (raw shared secret bytes)
   
3. Derive session_key = HKDF(shared_secret, info="ciphershift-msg", length=32) → AES-256 key.
4. nonce = os.urandom(12)` (96-bit nonce recommended by AES-GCM).
5. Build aad (associated data) to bind metadata to ciphertext. Example aad = f"{sender}|{recipient}|{timestamp}".encode().
6. ciphertext = AES_GCM.encrypt(session_key, nonce, plaintext, aad) → returns ciphertext+tag.
7. Append a message record to messages.json:

   ```json
   {
     "sender":"alice",
     "recipient":"bob",
     "timestamp":"2025-08-11T17:00:00Z",
     "nonce":"<base64>",
     "ciphertext":"<base64>",        // ciphertext + tag
     "kyber_ct":"<base64>",         // Kyber ciphertext
     "aad":"<base64>"               // optional, for ease of decryption
   }
   ```

8. The sender **does not** keep the AES key, shared secret, or any plaintext copy — only the stored ciphertext and kyber_ct remain.

**Result:** message cannot be re-encrypted/changed by the sender (they do not hold keys anymore) and AES-GCM provides integrity (tag).
---

## Detailed receiver flow (step-by-step)

1. Receiver logs in (password → PBKDF2/AES decrypt TOTP secret → OTP verify).
2. When viewing inbox, for each message targeted at them:

   * Read kyber_ct from message record.
   *  shared_secret = kyber.decapsulate(kyber_ct, receiver_private_key)`
   *  session_key = HKDF(shared_secret, info="ciphershift-msg", length=32)`
   *  AES_GCM_KEY = AESGCM(session_key)
   *  plaintext = AES_GCM_KEY.decrypt(nonce, ciphertext, aad)` → throws on tamper.
3. After Decrypt
   * Optionally delete kyber_ct (if desired).
     
5. The receiver’s Kyber private key itself is stored on the receiver’s workspace only.

---

## Message & metadata binding (use AAD)

* Use AES-GCM **Associated Data (AAD)** to bind metadata (sender/recipient/timestamp) to the ciphertext. This prevents an attacker from replacing metadata without invalidating the tag.
* Example: include `sender|recipient|timestamp` as AAD during encryption and verify it during decryption.

## Key lifecycle/message workflow(ASCII)

<img width="1415" height="266" alt="message_workflow_schematic diagram" src="https://github.com/user-attachments/assets/ac7730dc-524b-487b-a318-362af2fd4b6c" />

## Security guarantees & caveats

1. **Per-message forward secrecy**

   * **Each message uses a unique AES key derived from a one-time Kyber shared secret. Even if a later Kyber private key is exposed (after expiry), old messages remain protected if kyber\_ct or session keys were securely deleted.**
   * 
2. **Tamper detection & immutability**

   * AES-GCM provides an authentication tag — **any ciphertext tampering is detected upon decryption**.
   * **Sender immutability**: **because the sender deletes aes_key and shared_secret immediately after sending, they cannot re-encrypt or alter the message content later.**

3. **Metadata integrity**

   * Include metadata as **AAD** when encrypting so that metadata cannot be altered without causing decryption failure.

4. **Nonce handling**

   * Use a fresh 12-byte nonce per AES-GCM encryption. Because the AES key itself is unique per message, nonce reuse across messages is less catastrophic — but still avoid reuse to reduce complexity.

---

## Practical parameter recommendations

* AES-GCM: AES-256 (32-byte key). Nonce = 12 bytes (96 bits).
* HKDF: SHA-256, length = 32 bytes, `info=b"ciphershift-msg"`.
* Kyber: use the PQC parameter set adopted by `pqcrypto` you selected (e.g., Kyber512/768). (Follow your chosen library's defaults.)
* PBKDF2 for deriving AES key for TOTP secret: choose high iteration count (e.g., `>= 200000`) or use scrypt.

---
![Schematic diagram of the entire project architechture](https://github.com/user-attachments/assets/9c0fed05-976b-4697-b27e-e1a9f7854cde)


# Technologies Used

Language: Python 3

Libraries: pqcrypto (for CRYSTALS-Kyber KEM), cryptography.hazmat (for AES-256-GCM, PBKDF2, HKDF), bcrypt, os, pyotp, and base64.

Platform: Linux CLI (Kali/Ubuntu) and Windows.

2FA App: Aegis Authenticator.

Storage: JSON DB.

**Applications & Use Cases**:

Secure shift handovers in **SOC, NOC, SCADA,** and military systems.

Nurse shift updates on shared hospital terminals.

Forensic evidence transmission in air-gapped cyber labs.

Offline encrypted note sharing in confidential R&D or defense

## Future hardening (recommended but not yet implemented)

* **Sign each message** with Dilithium (post-quantum signature) for non-repudiation and tamper-evidence even if storage is mutable.
* Provide an **append-only audit log** where each write is timestamped and chained (e.g., HMAC chain or signed log).
* Consider storing `messages.json` in an encrypted, append-only file or a write-only service account so senders cannot alter past entries.

---
### Final Note:
#### This project is an original implementation of post-quantum cryptography in offline, shift-based secure messaging. It mimics the principles of TLS 1.3(confidentiality, integrity, and authenticity) within a completely local architecture.
#### It leverages AES-256-GCM, HKDF, PBKDF2, CRYSTALS-Kyber512, and offline TOTP (PyOTP) via Aegis. Every message is user-bound, ephemeral, and traceable—without ever touching the cloud.
#### This is a practical, next-generation secure messaging system designed for air-gapped, zero-trust, shift-based environments.
👥 Team

**Author: Zaid Ur Rahman Khan (BWU/BTA/22/003)**

**Project Guide: Mrs. Pranashi Chakraborty — Dept. of CSE AIML (BRAINWARE UNIVERSITY)**                                                                                                                                                                                  
