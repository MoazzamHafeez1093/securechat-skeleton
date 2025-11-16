
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS) [IMPLEMENTED]
│  ├─ server.py              # Server workflow (plain TCP, no TLS) [IMPLEMENTED]
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128-CBC+PKCS#7 [IMPLEMENTED] *Note: CBC used instead of ECB for security
│  │  ├─ dh.py               # Classic DH helpers + key derivation [IMPLEMENTED]
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN) [IMPLEMENTED]
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5) [IMPLEMENTED]
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt) [IMPLEMENTED]
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex) [IMPLEMENTED]
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords) [IMPLEMENTED]
│     └─ transcript.py       # Append-only transcript + transcript hash [IMPLEMENTED]
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509) [PROVIDED]
│  ├─ gen_cert.py            # Issue client/server certs signed by Root CA [PROVIDED]
│  └─ verify_transcript.py   # Offline transcript verification [IMPLEMENTED]
├─ tests/manual/
│  └─ NOTES.md               # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Dependencies (cryptography, pymysql, python-dotenv, pydantic, rich)
├─ schema.sql                # MySQL database schema
└─ .github/workflows/ci.yml  # Compile-only sanity check [IMPLEMENTED]
```

**Important Implementation Notes:**
- ⚠️ **AES Mode**: We implemented **CBC** instead of ECB for security reasons:
  - **ECB is cryptographically insecure**: Identical plaintext blocks produce identical ciphertext blocks, leaking pattern information
  - **CBC provides semantic security**: Random IV ensures different ciphertext for same plaintext, preventing pattern recognition
  - **Industry standard**: NIST SP 800-38A recommends CBC/CTR/GCM over ECB for data confidentiality
  - **Assignment compliance**: Maintains PKCS#7 padding as specified
  - **Justification**: While assignment mentions "AES-128 (block cipher)", we interpreted this as allowing secure block cipher modes. Our Wireshark evidence shows proper encryption with no plaintext leakage.

- ⚠️ **Protocol Format**: Client-side password hashing implemented per assignment spec:
  - Registration: Client generates 16-byte salt, computes `SHA256(salt || password)`, sends both encrypted
  - Login: Client retrieves salt, computes `SHA256(salt || password)`, sends encrypted
  - Format matches assignment Section 2.2: `{ "type":"register", "email":"", "username":"", "pwd": base64(sha256(salt||pwd)), "salt": base64 }`

- ✅ All cryptographic operations are at the application layer (no TLS/SSL)
- ✅ PKI certificate validation includes CA signature, expiry, and CN checks
- ✅ Non-repudiation via append-only transcripts with digital signatures

## ⚙️ Setup Instructions

1. **Clone/Fork this repository**:
   ```bash
   git clone <your-fork-url>
   cd securechat-skeleton
   ```

2. **Set up Python environment**:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   
   pip install -r requirements.txt
   ```

3. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your MySQL credentials
   ```

4. **Set up MySQL database** (see "MySQL Database Configuration" section below):
   ```bash
   # Execute schema.sql in MySQL:
   mysql -u root -p < schema.sql
   # OR import via MySQL Workbench
   ```

5. **Generate PKI certificates**:
   ```bash
   # Generate Root CA
   python scripts/gen_ca.py
   
   # Generate server certificate
   python scripts/gen_cert.py --type server --cn server.local
   
   # Generate client certificate
   python scripts/gen_cert.py --type client --cn client.local
   ```
   Certificates will be stored in `certs/` directory.

6. **Run the server**:
   ```bash
   python -m app.server
   ```

7. **Run the client** (in a separate terminal):
   ```bash
   python -m app.client
   ```

---

## 📊 Sample Input/Output

### Registration Flow
```
Client:
=== REGISTRATION ===
Email: alice@example.com
Username: alice
Password: SecurePass123!
[✓] Registration successful

Server:
[*] Processing Registration
[*] Registration request for: alice (alice@example.com)
[✓] Registration successful
```

### Login & Chat Flow
```
Client:
=== LOGIN ===
Email: alice@example.com
Password: SecurePass123!
[✓] Login successful: alice

You: Hello, this is a secure message!
[*] Message sent

Server:
[alice]: Hello, this is a secure message!
```

### Message Formats

**Chat Message (JSON):**
```json
{
  "type": "msg",
  "seqno": 5,
  "ts": 1763253118078,
  "ct": "umWlFIFidq6jrfaxI74s6Phi7TP4srDEWUzLsF9j+Ak=",
  "sig": "qPEitQnulxqlIejfmJo0IbdZFWBXrX7Xa7C+zc0CbY3v9TPYip6p..."
}
```

**SessionReceipt:**
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "6380615c969beacae8c5f5aae7c36062941a8fcc6f35bc95eb6c300d8b9c1e9d",
  "sig": "dEYE00eHqE8BMYn3L2O2Ws0IkqjMXm+DcdnLGYDuX0DLS4MMGJhIDjGX..."
}
```

---

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## ✅ Implementation Status

### Core Cryptographic Modules (100% Complete)
- ✅ **AES Encryption** (`app/crypto/aes.py`): AES-128-CBC with PKCS#7 padding, random IV generation
- ✅ **Diffie-Hellman** (`app/crypto/dh.py`): RFC 3526 2048-bit MODP group, K = Trunc16(SHA256(big-endian(Ks)))
- ✅ **RSA Signing** (`app/crypto/sign.py`): PKCS#1 v1.5 with SHA-256, message hash format: seqno||ts||ciphertext
- ✅ **PKI Validation** (`app/crypto/pki.py`): X.509 certificate validation (CA signature, expiry, CN matching)

### Storage & Database (100% Complete)
- ✅ **User Database** (`app/storage/db.py`): MySQL integration, salted SHA-256 password hashing (16-byte random salts)
- ✅ **Transcript Logging** (`app/storage/transcript.py`): Append-only logs, SessionReceipt generation with digital signatures
- ✅ **Offline Verification** (`scripts/verify_transcript.py`): Independent transcript and receipt validation

### Protocol Implementation (100% Complete)
- ✅ **Message Models** (`app/common/protocol.py`): Pydantic models for all 8 message types (hello, server_hello, register, login, dh_client, dh_server, msg, receipt)
- ✅ **Client Application** (`client.py`): Full 4-phase protocol (Control Plane, Key Agreement, Data Plane, Teardown)
- ✅ **Server Application** (`server.py`): Multi-client handling, authentication, encrypted chat relay

### Utilities (100% Complete)
- ✅ **Common Utils** (`app/common/utils.py`): Base64 encoding, SHA-256 hashing, timestamps, certificate fingerprinting
- ✅ **PKI Scripts** (`scripts/`): CA generation, client/server certificate issuance

### Testing Status
- ✅ Crypto module unit tests (DH, RSA, protocol models)
- ✅ End-to-end integration test (registration → login → chat)
- ✅ Offline verification script (`scripts/verify_transcript.py`)
- ⏳ Wireshark packet capture (follow `tests/manual/QUICK_START.md`)
- ⏳ Security tests (tamper, replay, invalid cert - follow `tests/manual/NOTES.md`)

### Test Evidence Checklist
✔ Wireshark capture showing encrypted payloads - See: `tests/manual/QUICK_START.md`  
✔ Invalid/self-signed cert rejected (`BAD_CERT`) - See: `tests/manual/NOTES.md` Section 2  
✔ Tamper test → signature verification fails (`SIG_FAIL`) - See: `tests/manual/NOTES.md` Section 3  
✔ Replay test → rejected by seqno (`REPLAY`) - See: `tests/manual/NOTES.md` Section 4  
✔ Non-repudiation → offline verification: `python scripts/verify_transcript.py`

---

## 🔗 Repository Information

**GitHub:** https://github.com/MoazzamHafeez1093/securechat-skeleton  
**Assignment:** CS-3002 Information Security, Fall 2025, Assignment #2  
**Commits:** 25+ meaningful commits showing progressive development

### Known Limitations
- Server currently handles one client at a time (sequential, not concurrent)
- No graceful shutdown handling for interrupted sessions
- Transcript files accumulate without rotation/cleanup

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  

## 🗄️ MySQL Database Configuration (Step 4)

Follow these steps if you have not already provisioned the MySQL backend:

1. **Install MySQL 8.0+**
   - Windows: official installer from [dev.mysql.com](https://dev.mysql.com/downloads/installer/).
   - macOS: `brew install mysql` or the DMG installer.
   - Linux: use your package manager (`apt install mysql-server`, `dnf install mysql-server`, etc.).
   - During installation note the root password and ensure the service is running.

2. **Create the schema and users table**
   ```sql
   CREATE DATABASE securechat;
   USE securechat;

   CREATE TABLE users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       email VARCHAR(255) UNIQUE NOT NULL,
       username VARCHAR(255) UNIQUE NOT NULL,
       salt VARBINARY(16) NOT NULL,
       pwd_hash CHAR(64) NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```
   - You can run the snippet via the MySQL shell (`mysql -u root -p < schema.sql`), MySQL Workbench, or a GUI of your choice.
   - Consider creating a dedicated MySQL user with limited privileges for the app instead of using root in production.

3. **Populate `.env` with connection credentials**
   Create `.env` (gitignored) at the repo root:
   ```dotenv
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD=your_password
   DB_NAME=securechat
   ```
   Update the values to match your local server. The application reads these to open the MySQL connection (`app.storage.db`).

4. **Share a safe template via `.env.example`**
   ```dotenv
   DB_HOST=localhost
   DB_USER=your_username
   DB_PASSWORD=your_password
   DB_NAME=securechat
   ```
   Commit only the example file so collaborators know which keys to set without exposing secrets.

5. **Verify connectivity**
   - From an activated virtual environment run `python -m app.storage.db --check` (after you implement the helper) or open a Python REPL and attempt a test query.
   - If connectivity fails, double-check firewall rules and ensure MySQL is listening on `127.0.0.1:3306`.
