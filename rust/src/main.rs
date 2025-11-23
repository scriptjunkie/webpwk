// webpwk - web password based keying - example server
// Defends against exposed secrets (passwords) in use or in transit like how hashing defends
// against exposing passwords at rest.

// Instead of sending the password directly, the client first derives an asymmetric key pair
// from the password using a key derivation function (KDF). The client then sends a request to
// /challenge, and the server replies with a challenge. The client then signs the challenge with
// its private key and sends the signature back to the server. The server then verifies the
// signature with the public key. If the signature is invalid, the server returns an error message.

// If the signature is valid, the server continues with the normal logon or registration process,
// treating the public key as the password.

// This example server is a simple HTTP server that implements the above protocol. Data is stored
// in the filesystem for simplicity. Challenges are stored in memory and removed after use.
// /register checks to see if the name has already been registered and if not, creates a
// new folder whose name is the hex encoding of the provided username. Inside the folder, it stores a file
// called "salt" containing a random salt, and a file called "hmac" containing the HMAC of the
// public key and salt.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex;
use hmac::{Hmac, Mac};
use rand::prelude::*;
use rouille::Response;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::io::Read;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

//Challenges for this demonstration are stored in a BTreeSet.
static CHALLENGES: Mutex<BTreeSet<[u8; 32]>> = Mutex::new(BTreeSet::new());
pub fn main() {
    rouille::start_server("127.0.0.1:2203", move |request| {
        println!("handling request {}", request.raw_url());

        //Step 1: client requests challenge, server generates random 32 byte challenge and returns it
        if request.raw_url() == "/challenge" {
            let challenge: [u8; 32] = rand::rng().random(); //generate challenge
            CHALLENGES.lock().ok().map(|mut set| set.insert(challenge)); //save challenge
            // Remove the challenge after 10 seconds so it times out
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(10));
                CHALLENGES.lock().ok().map(|mut set| set.remove(&challenge));
            });
            return Response::from_data("application/octet-stream", challenge).with_no_cache();
        }

        //Step 2: client sends public key, challenge, and signature, server validates crypto
        let mut buf = [0u8; 32 + 64 + 32];
        let pubkey = if let Some(mut data) = request.data()
            && let Ok(_) = data.read_exact(&mut buf)
            && let Ok(rawpubkey) = <&[u8; 32]>::try_from(&buf[..32])
            && let Ok(rawsig) = <&[u8; 64]>::try_from(&buf[32..32 + 64])
            && let Ok(public_key) = VerifyingKey::from_bytes(rawpubkey)
        {
            let signature = Signature::from_bytes(rawsig);
            if let Err(_) = public_key.verify(&buf[32 + 64..], &signature) {
                return Response::text("Bad signature!").with_status_code(401); //bad signature
            }
            rawpubkey //good signature! Save public key that has now been verified.
        } else {
            return Response::text("Failed to read body").with_status_code(400); //not enough data
        };
        let challenge = &buf[32 + 64..32 + 64 + 32]; //we already know challenge is 32 bytes

        //Step 3: See if challenge exists and delete it if so. This ensures that the challenge is only used once.
        if let Ok(c) = <&[u8; 32]>::try_from(challenge)
            && !CHALLENGES.lock().map(|mut s| s.remove(c)).unwrap_or(false)
        {
            return Response::text("Challenge not found").with_status_code(401);
        }

        //Step 4: Continue like a normal logon or registration treating pubkey as the password
        //name must be present for login/registration and between 1 and 64 characters long
        let h = request.header("name");
        let name = if let Some(n) = h.filter(|n| !n.is_empty() && n.len() < 64) {
            n
        } else {
            return Response::text("Missing or bad name").with_status_code(400);
        };
        let namehex = hex::encode(name.as_bytes());
        let mut hmac = match HmacSha256::new_from_slice(pubkey) {
            Ok(hmac) => hmac,
            Err(_) => return Response::text("Failed to create HMAC").with_status_code(500),
        };
        if request.raw_url() == "/register" {
            //see if account exists
            if std::fs::metadata(&namehex).is_ok() {
                return Response::text("User already registered").with_status_code(400);
            }
            let salt: [u8; 32] = rand::rng().random(); //get random salt
            hmac.update(&salt); //hmac pubkey and salt
            let hmac_bytes = hmac.finalize().into_bytes();
            //write salt and hmac
            if std::fs::create_dir_all(&namehex).is_err()
                || std::fs::write(format!("{}/salt", &namehex), &salt).is_err()
                || std::fs::write(format!("{}/hmac", &namehex), &hmac_bytes).is_err()
            {
                if let Err(e) = std::fs::remove_dir_all(&namehex) {
                    //on error, try to undo everything
                    eprintln!("Failed to remove directory: {}", e);
                }
                return Response::text("Failed to write files").with_status_code(500);
            }
            Response::text("Registration complete")
        } else if request.raw_url() == "/login" {
            if std::fs::metadata(&namehex).is_err() {
                return Response::text("User not registered").with_status_code(401);
            }
            //read salt, hmac.
            if let Ok(salt) = std::fs::read(format!("{}/salt", &namehex))
                && let Ok(hmac_bytes) = std::fs::read(format!("{}/hmac", &namehex))
            {
                //The client is already verified to own the key, now verify the key is for this user by testing hmac
                hmac.update(&salt);
                if hmac.verify_slice(&hmac_bytes).is_err() {
                    return Response::text("Invalid credentials").with_status_code(401);
                }
                Response::text(format!("Login successful for {}", name))
            } else {
                Response::text("Failed to read files").with_status_code(500)
            }
        } else {
            Response::empty_404()
        }
    });
}
