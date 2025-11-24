# webpwk - Web Password-Based Keying

Authentication that defends against exposing passwords in use or in transit, similar to how hashing defends against exposing passwords at rest.

## Motivation

Any website that keeps unhashed passwords would be mocked as negligent, since password databases have been exposed hundreds or thousands of times, including for many of the biggest websites in the world.

Unfortunately, sites still receive and hold passwords in memory during authentication, and many breaches have exposed passwords through memory disclosures, like Heartbleed and exposed crash dumps, or passive interception of requests after decryption.

This is a curious vulnerability, as resolving it does not require any user-visible changes, and with all modern browsers, it also no longer requires complex code on either the client or the server.

This project implements such a system, with client implementation in a few lines of JavaScript ( < 1kB minified, < 500 bytes gzipped), and example server implementations in both Rust and Python at [https://github.com/scriptjunkie/webpwk](https://github.com/scriptjunkie/webpwk).

## Usage

### Client side changes
Without NPM, simply copy the proof function into your code and use as demonstrated in [login.html](login.html).

Using NPM, add the webpwk package to your project dependencies. Then in your JavaScript code, import the package and upon submitting a login, instead of submitting the password, get a challenge from the server and submit the result of `await proof(password, challenge)`.

```javascript
import { proof } from 'webpwk';
const challenge = new Uint8Array(await (await fetch('challenge')).arrayBuffer());
let response = await fetch('login', {method: 'POST', body: await proof(password.value, challenge)});
```

This example simply receives the challenge as 32 binary bytes then sends the authentication data in 128 bytes of binary. It's small, but a good habit where possible to save bytes, milliseconds, and kWh. If, however, you need to send the data as text, embed in JSON, etc., call the toBase64() method on the Uint8Array returned by proof(): `(await proof(password.value, challenge)).toBase64()` and then decode the base64 string on the server before the validation code.

### Server side changes

See example code in the server folders, e.g. [rust](https://github.com/scriptjunkie/webpwk/tree/master/rust) and [python](https://github.com/scriptjunkie/webpwk/tree/master/python).

## Implementation Overview

Instead of sending passwords directly over the network, webpwk uses a challenge-response authentication protocol with Ed25519 asymmetric cryptographic signatures:

1. **Client derives a key pair** from the password using a Key Derivation Function (KDF)
2. **Client requests a challenge** from `/challenge` endpoint
3. **Server generates and returns** a random 32-byte challenge (valid for 10 seconds)
4. **Client signs the challenge** with their private key
5. **Client sends** public key + challenge + signature
6. **Server verifies** the signature and continues with authentication

This ensures passwords never traverse the network or are held in memory on the server, even during authentication, and ensures that any authentication information in memory, such as the signatures, cannot be replayed.

## Running the Rust Server

[Rust server folder](https://github.com/scriptjunkie/webpwk/tree/master/rust)

```bash
cd rust
cargo run
```

Then open `http://127.0.0.1:2203` in your browser.

## Running the Python Server

[Python server folder](https://github.com/scriptjunkie/webpwk/tree/master/python)

```bash
cd python
pip install -r requirements.txt
python main.py
```

Then open `http://127.0.0.1:2203` in your browser.
