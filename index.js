// This function is the primary function to generate password derived key and create a proof of possession
// Default iterations are in accordance with OWASP guidelines. OWASP Password Storage Cheat Sheet (current as of 2025):
// "If FIPS-140 compliance is required, use PBKDF2 with a work factor of 600,000 or more and set with an internal hash
// function of HMAC-SHA-256."
export async function proof(password, challenge, client_salt = 'pkpassword', iterations = 600000, hash = 'SHA-256') {
    // Convert password string to key bytes with PBKDF2 and get challenge as bytes too
    const encoded = (new TextEncoder()).encode(password);
    const key = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveBits']);
    const salt = (new TextEncoder()).encode(client_salt);
    let bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', iterations, salt, hash }, key, 256));

    //Convert key to PKCS8 for Ed25519 by appending to static header
    let pkcs8 = Uint8Array.fromBase64('MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    pkcs8.set(new Uint8Array(bits), 16);
    const ed = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);

    let output = new Uint8Array(32 + 64 + challenge.length);
    let jwk = await crypto.subtle.exportKey("jwk", ed);
    let binpub = Uint8Array.fromBase64(jwk.x.replaceAll('-', '+').replaceAll('_', '/'));
    output.set(binpub, 0);
    output.set(new Uint8Array(await crypto.subtle.sign('Ed25519', ed, challenge)), 32);
    output.set(challenge, 32 + 64);
    return output;
}
