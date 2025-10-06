Secure Programming — Overlay Chat System 

Project: Group implementation of the Advanced Secure Programming assignment — a distributed overlay multi-party chat system that implements the class-standardised protocol.
Purpose of this repo: submit the backdoored implementation (for peer review) together with run instructions, tests, and the SRS.

⚠️ Important: This repository contains intentional, ethically-limited backdoors required by the assignment. Do not run this code on production machines. Use an isolated VM or sandbox.

Table of Contents

Repository structure

Quick start (run in 5 steps)

Prerequisites & installation

Key generation & secure storage

Running a node (CLI)

Demo: run 3 local nodes

Commands / Example sessions

Tests & static analysis

Security features & design notes

Intentional backdoors (high level)

Mapping: SRS FR/NFR → source files (suggested)

Troubleshooting & FAQs

Authors & branches

License & contact

Repository structure
Secure-Programming/
├── README.md                        # (this file)
├── SRS.md                           # Software Requirements Specification
├── src/                             # Source code implementation
│   ├── main.py                      # Entry point for the chat node (Python example)
│   ├── crypto/
│   │   ├── keys.py                  # key generation, load/save
│   │   ├── aead.py                  # AEAD wrappers (encrypt/decrypt)
│   │   └── signing.py               # digital signature utilities
│   ├── protocol/
│   │   ├── handshake.py
│   │   ├── messages.py
│   │   └── file_transfer.py
│   ├── routing/
│   │   ├── table.py
│   │   └── forwarder.py
│   ├── network/
│   │   ├── server.py
│   │   └── client.py
│   └── utils/
│       ├── logger.py
│       └── config.py
├── tests/
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_routing.py
│   └── test_endtoend.py
├── demo/
│   └── run_demo.sh
├── requirements.txt                  # (if Python) dependencies
├── docs/
│   └── protocol_design.md
└── scripts/
    └── helpers.sh


If your group used another language (Rust/Go/C), analogous files are present in branches (e.g., Cargo.toml in Rust branch). Replace Python commands with the language-specific steps.

Quick start (run in 5 steps)

Clone the repo and change into it.

Install dependencies (see below).

Generate keys.

Start one node (bootstrap or standalone).

Use the CLI to list peers and send messages.

Prerequisites & installation

Recommended environment: Ubuntu 20.04+ or any Linux VM. Use isolated VM for running untrusted/backdoored submissions.

Python implementation (example)

Python 3.10+ installed.

Create a virtualenv:

python3 -m venv venv
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt


(If your group's implementation is Rust/Go/C, follow the corresponding branch README — e.g., cargo build --release for Rust.)

Key generation & secure storage

Private keys must be protected (file permissions and optional passphrase recommended).

Example commands (Python wrapper in src/crypto/keys.py):

# generate keys (private and public) into ./keys/
python src/crypto/keys.py --gen --out keys/

# check keys
ls -l keys/
# ensure permissions are 600:
chmod 600 keys/private.key


Notes:

We use an Ed25519 (signing) + X25519 (key agreement) approach in the Python implementation.

Store keys under keys/ (gitignore them in real projects). For the assignment submission, the repository may include a sample keypair for reproducibility — but do NOT use real personal keys.

Running a node (CLI)

Start node (bootstrap to an existing peer):

python src/main.py start --bootstrap 127.0.0.1:5000 --bind 0.0.0.0:5001 --keys ./keys/


Start node (standalone, no bootstrap):

python src/main.py start --bind 0.0.0.0:5001 --keys ./keys/


Stop node:

python src/main.py stop


Status:

python src/main.py status


List peers:

python src/main.py list
# output example:
# PEER_ID  ADDRESS        LAST_SEEN  KEY_FINGERPRINT
# nodeA    10.0.0.3:5001  2025-10-05  ab:cd:ef...


Send private message:

python src/main.py send --to <peer_id> --msg "Hello, this is Rakib"


Broadcast message:

python src/main.py broadcast --msg "Hello everyone"


Send file:

python src/main.py sendfile --to <peer_id> --file /path/to/file

Demo: run 3 local nodes

A helper script is included to spawn three nodes locally (demo uses ports 5001, 5002, 5003):

chmod +x demo/run_demo.sh
./demo/run_demo.sh


This will:

create three keypairs in demo/keys/node1, demo/keys/node2, demo/keys/node3 (or reuse sample keys),

start three node processes,

show a sample private and broadcast message flow.

Stop the demo with:

pkill -f src/main.py

Commands / Example sessions

1) Start node:

python src/main.py start --bind 127.0.0.1:5001 --keys keys/


2) From node A, list:

> nodeA$ python src/main.py list
nodeB 127.0.0.1:5002 last_seen: 2025-10-05T21:10Z
nodeC 127.0.0.1:5003 last_seen: 2025-10-05T21:10Z


3) Private message:

> nodeA$ python src/main.py send --to nodeB --msg "hey nodeB"
(nodeB displays) [nodeA] hey nodeB


4) File transfer:

> nodeA$ python src/main.py sendfile --to nodeB --file ./testdata/sample.txt
# displays progress, per-chunk verification, and final SHA-256 checksum validation

Tests & static analysis

Run unit tests:

pytest tests/


Run the end-to-end integration test:

python tests/test_endtoend.py


Static analysis (Python example):

# security-focused lint
bandit -r src/

# general lint
flake8 src/


Rust/Go branches: use cargo test / go test respectively.

Security features & design notes

Mutual authentication: Each peer uses a long-term signing key (Ed25519) and ephemeral X25519 keys for session key derivation.

Confidentiality & Integrity: AEAD (AES-GCM or ChaCha20-Poly1305) used for message payloads.

Replay protection: Messages include sequence numbers and nonce windows.

Routing: Overlay routing table with TTL; forwarders avoid cycles using TTL and seen-message caches.

File transfer: Chunked transfer with per-chunk HMAC and final SHA-256 checksum.

Logging: Configurable levels; logs intentionally avoid printing private keys or raw plaintext messages.

Key protection: Private key files are stored with strict file permissions; an optional passphrase encryption wrapper is supported.

Intentional backdoors (high level)

Per assignment rules, this submission contains two intentionally placed vulnerabilities (backdoors). These are documented only in the reflective commentary appendix (submitted separately) and are not explained in detail here to preserve the peer-review exercise integrity.

High-level constraints on these backdoors:

They only affect the running process and the overlay chat environment.

They are demonstrable and exploitable in a sandbox/VM only (no host compromise).

They are authored ethically: no covert exfiltration to external servers etc.

If you are reviewing this code for your coursework, treat this repo as potentially malicious and run it in a VM/sandbox.

Mapping: SRS FR/NFR → source files (suggested)

Use this table in peer reviews. Update it to match your final code layout.

FR-1.1  => src/main.py::start/stop/status
FR-2.1  => src/network/server.py::bootstrap_connect
FR-2.2  => src/protocol/messages.py::handle_LIST
FR-3.1  => src/crypto/keys.py::generate_keypair
FR-3.2  => src/protocol/handshake.py::verify_peer_signature
FR-3.3  => src/protocol/handshake.py::derive_session_keys
FR-4.1  => src/protocol/messages.py::send_private
FR-4.2  => src/protocol/messages.py::send_group
FR-4.3  => src/protocol/messages.py::message_framer
FR-5.1  => src/protocol/file_transfer.py::init_transfer
FR-5.2  => src/protocol/file_transfer.py::chunk_transfer
FR-6.1  => src/routing/table.py::update_table
FR-6.2  => src/routing/forwarder.py::forward_message
FR-7.1  => src/utils/logger.py
FR-8.1  => backdoored submission branch (documented in reflective commentary)

Troubleshooting & FAQs

Q: Node won't start — Address already in use
A: Another process is using the requested port. Use a different --bind port or stop the other process.

Q: Keys not loaded / permission denied
A: Ensure keys/private.key has permission 600 and is readable by the process owner only.

Q: Messages are not delivered to remote peers
A:

Verify peers are reachable (firewall, NAT).

Check the routing table: python src/main.py list and python src/main.py status.

Confirm handshake succeeded (look at logs at INFO/DEBUG level).

Q: How do I run the backdoor-free build?
A: See the branch named backdoor-free (or run the make clean-build script). For submission, both versions are included per assignment instructions.

Authors & branches

Group members (example):

Masud Ahammad
Nguyen Duc Tung Bui
Guilin Luo
Mazharul Islam Rakib
Muhammad Tayyab Rashid


Main branches to check:

master — canonical submission (backdoored)

backdoor-free — version without intentional backdoors (for reflective submission)

dev, frontend, and member branches (rakib, Jeff) — experimental contributions

License & contact

This code is provided for the University assignment and educational use only. Do not reuse outside the assignment context without permission.

