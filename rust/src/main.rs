use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use rouille::Response;
use std::convert::TryFrom;
use std::io::Read;

pub fn main() {
	rouille::start_server("127.0.0.1:2203", move |request| {
		println!("handling request {}", request.raw_url());

		//Step 1: read in the body and validate the crypto
		let mut buf = Vec::with_capacity(512);
		if let Some(mut data) = request.data()
				&& let Ok(_) = data.read_to_end(&mut buf) 
				&& buf.len() > 32 + 64
				&& let Ok(rawpubkey) = <&[u8; 32]>::try_from(&buf[..32])
				&& let Ok(rawsig) = <&[u8; 64]>::try_from(&buf[32..32 + 64])
				&& let Ok(public_key) = VerifyingKey::from_bytes(rawpubkey){
			let signature = Signature::from_bytes(rawsig);
			if let Ok(_) = public_key.verify(&buf[32 + 64..], &signature){
				println!("Signature passed!");
			} else {
				return Response::text("Bad signature!");
			}
		} else {
			return Response::text("Failed to read body");
		}
		let pubkey = &buf[..32];
		let challenge = &buf[32 + 64..];

		//Step 2: the crypto is good, now we can continue similar to a normal logon or registration treating pubkey as the password
		//decode challenge and get name out
		//name = json...
		//hash name to hex
		//namehashhex = hex...
		if(request.raw_url() == "/register"){
			//see if namehashhex exists
			//fout = openoptions...
			//get random salt
			//salt = random...
			//hmac pubkeyhex and salt
			//hmac = hmac...
			//write salt and hmac and name to file with name hash. note that this could be sql insert (user, salt, hash)
			Response::text("Registration complete")
		} else {
			//see if namehashhex exists
			//fin = openoptions...
			//read salt, hmac, name
			//read...
			//test hmac(salt, pubkey) == hmac
			//if...
			//if good, return "welcome {name}"
			Response::text("Welcome")
		}
	});
}
