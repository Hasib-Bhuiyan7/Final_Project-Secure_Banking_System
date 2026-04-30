# Final_Project-Secure_Banking_System

## Overview

This project presents the design and implementation of a **secure banking system architecture** consisting of a centralized bank server and multiple concurrent ATM client machines. The system operates over an untrusted network and is built with the primary objective of ensuring **secure, authenticated, and integrity-protected communication** between clients and the server.

The application simulates real-world financial interactions, including **account registration, authentication, deposits, withdrawals, and balance inquiries**, while integrating modern cryptographic techniques and secure communication protocols. The implementation reflects fundamental principles used in real-world systems such as TLS-like key derivation, message authentication, and replay attack prevention.

At its core, the system demonstrates how a **pre-shared key (PSK)** can be transformed into secure, session-specific cryptographic material, enabling confidential and tamper-proof communication between distributed components.

---

## System Architecture

The system follows a **concurrent client-server model**, where:

* The **ATM Client** serves as the user-facing interface
* The **Bank Server** acts as the centralized backend authority
* Communication occurs over **TCP/IP sockets (port 50000)**
* Each client connection is handled in a **dedicated thread**

### Key Components

**ATM Client Module**

* GUI-based frontend implemented using Tkinter
* Handles user interaction (login, register, transactions)
* Establishes secure socket connection to server
* Performs cryptographic handshake and secure message transmission

**Bank Server Module**

* Multi-threaded backend system
* Handles concurrent client sessions
* Manages authentication and transaction logic
* Maintains persistent account database
* Enforces cryptographic verification and replay protection

**Subcomponents**

* **Listener/Thread Manager**: Accepts incoming connections and spawns threads
* **Crypto Engine**: Handles key derivation, encryption, and MAC verification
* **Account Database**: Stores user credentials and balances (`accounts.dat`)
* **Audit Log System**: Securely records all user actions (`audit.log`)

---

## Key Authentication Protocol

The authentication mechanism is based on a **Pre-Shared Key (PSK) combined with nonce exchange**.

* The client generates a **random nonce** and sends it to the server
* The server responds with its own **random nonce**
* Both parties derive a shared **Master Secret** using:

  * PSK
  * Client nonce
  * Server nonce

This approach ensures that:

* Only legitimate participants can derive the session keys
* Each session produces **unique cryptographic material**
* Authentication is implicitly achieved through **successful MAC verification**

---

## Key Derivation Strategy (HKDF-Based)

A secure **HMAC-based Key Derivation Function (HKDF)** is used to derive session keys.

### Process

1. **Master Secret Derivation**

   * Derived from PSK + nonces
   * Ensures session uniqueness and freshness

2. **Key Expansion**

   * Master secret expanded into:

     * **Encryption Key (32 bytes)**
     * **MAC Key (32 bytes)**

### Security Properties

* Enforces **key separation**
* Prevents key reuse vulnerabilities
* Ensures **forward secrecy-like behavior (per session uniqueness)**
* Resistant to replay and key recovery attacks

This design closely mirrors modern secure protocols such as TLS.

---

## Secure Communication Protocol

All communication follows an **Encrypt-then-MAC** scheme:

### Encryption Flow

1. Plaintext is encrypted using **Fernet (AES-based symmetric encryption)**
2. HMAC (SHA-256) is computed over the ciphertext
3. Transmitted message contains:

   * Base64-encoded ciphertext
   * Corresponding HMAC

### Decryption Flow

1. HMAC is recomputed and verified
2. Only if verification succeeds → ciphertext is decrypted

This ensures:

* **Confidentiality** (data is encrypted)
* **Integrity** (tampering is detected)
* **Authentication** (only valid parties can generate correct MACs)

---

## Replay Attack Protection

To prevent replay attacks:

* Each request includes a **timestamp**
* Server maintains a **last_timestamp per session**
* Any request with:

  * Older timestamp
  * Duplicate timestamp
    → is **rejected as a replay attack**

This ensures **message freshness** and prevents attackers from reusing intercepted packets.

---

## Transaction System

Supported operations include:

* User Registration
* User Login
* Deposit
* Withdraw
* Balance Inquiry

### Security Enforcement

* Transactions require authenticated session
* Input validation (e.g., no negative deposits)
* Thread-safe execution using `threading.Lock()`
* Atomic updates to account database

---

## Data Storage

**Accounts Database (`accounts.dat`)**

* Stores username, password, and balance
* Serialized using `pickle`
* Protected by thread synchronization

**Note:** Passwords are stored in plaintext due to project scope limitations. In real systems, hashing + salting would be required.

---

## Secure Audit Logging

All system activities are recorded in an **encrypted audit log**.

### Features

* Logs include:

  ```
  Username    ACTION    Timestamp
  ```
* Each entry is encrypted using a **dedicated Fernet key**
* Stored in `audit.log`

### Security Benefits

* Prevents exposure of sensitive transaction history
* Protects logs even if server is compromised
* Supports **non-repudiation** and traceability

A separate decryption tool is provided for authorized log inspection.

---

## Concurrency & Performance

* Server supports **multiple simultaneous clients**
* Each connection runs in an independent thread
* Ensures:

  * No blocking between clients
  * Consistent account updates
  * Scalable design

---

## Security Properties Achieved

The system successfully enforces:

* **Confidentiality**: All data is encrypted
* **Integrity**: HMAC detects any tampering
* **Authentication**: Only valid parties derive correct keys
* **Replay Protection**: Timestamp validation blocks reused messages
* **Non-Repudiation**: Encrypted audit logs track all actions

---

## Implementation Highlights

* HKDF-based key derivation (secure and modular)
* Encrypt-then-MAC communication design
* Thread-safe banking operations actively enabling multiple client connections
* GUI-based ATM client interface
* Encrypted audit logging with offline inspection tool
* Modular and maintainable code structure
  
---

## Conclusion

This project demonstrates a **complete secure communication system** that integrates concepts from:

* Network Security
* Cryptography
* Concurrent Programming
* Secure Software Design

By combining **HKDF-based key derivation, symmetric encryption, MAC verification, and replay protection**, the system provides a strong foundation for understanding how real-world secure banking systems operate.

It reflects not only theoretical knowledge but also practical implementation of **secure protocols, modular design, and system-level thinking**, making it a comprehensive demonstration of applied network security principles.


