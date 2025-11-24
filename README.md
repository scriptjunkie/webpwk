# webpwk - Web Password-Based Keying

Authentication that defends against exposing passwords in use or in transit, similar to how hashing defends against exposing passwords at rest.

## Motivation

Any website that keeps unhashed passwords would be mocked as negligent, since password databases have been exposed hundreds or thousands of times, including for many of the biggest websites in the world.

Unfortunately, sites still hold passwords in memory during authentication, and many breaches have exposed passwords through memory disclosures, like Heartbleed and exposed crash dumps, or passive interception of requests after decryption.

This is a curious vulnerability, as resolving it does not require any user-visible changes, and with all modern browsers, it also no longer requires complex code on either the client or the server.

This project implements such a system, with client implementation in a few lines of JavaScript, and simple server implementations in both Rust and Python.

## Overview

Instead of sending passwords directly over the network, webpwk uses a challenge-response authentication protocol with Ed25519 asymmetric cryptographic signatures:

1. **Client derives a key pair** from the password using a Key Derivation Function (KDF)
2. **Client requests a challenge** from `/challenge` endpoint
3. **Server generates and returns** a random 32-byte challenge (valid for 10 seconds)
4. **Client signs the challenge** with their private key
5. **Client sends** public key + challenge + signature
6. **Server verifies** the signature and continues with authentication

This ensures passwords never traverse the network or are held in memory on the server, even during authentication, and ensures that any authentication information in memory, such as the signatures, cannot be replayed.

## Running the Rust Server

```bash
cd rust
cargo run
```

Then open `http://127.0.0.1:2203` in your browser.

## Running the Python Server

```bash
cd python
pip install -r requirements.txt
python main.py
```

Then open `http://127.0.0.1:2203` in your browser.
