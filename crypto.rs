use crate::types::*;
use gpgme::{
    context::Context,
    Protocol::OpenPgp,
    SignMode,
    SignatureSummary,
};

pub fn verify_key_authorized(authorized_keys: &Vec<String>, key: &String) -> Result<ResultTypes, ResultTypes> {
    if !authorized_keys.contains(&key) { return Err(ResultTypes::UnauthKey); }
    Ok(ResultTypes::OK)
}

pub fn decrypt(enc_data: &Vec<u8>) -> Result<Vec<u8>, ResultTypes> {
    let mut gpg_ctx = Context::from_protocol(OpenPgp).unwrap();
    let mut dec_data = vec![];
    match gpg_ctx.decrypt(enc_data, &mut dec_data) {
        Ok(_) => return Ok(dec_data),
        Err(_) => return Err(ResultTypes::DecryptionError),
    }
}

pub fn get_sign_key_fpr(key_id: &String) -> Result<String, ResultTypes> {
    let mut gpg_ctx = Context::from_protocol(OpenPgp).unwrap();
    match gpg_ctx.locate_key(key_id) {
        Ok(key) => {
            let subkeys = key.subkeys();
            for key in subkeys {
                if key.can_sign() {
                    return Ok(key.fingerprint()?.to_string());
                }
            }
            return Err(ResultTypes::KeyNoSigAttr);
        },
        Err(_) => return Err(ResultTypes::UnregisteredKey),
    }
}

pub fn sign_data(data: Vec<u8>, key_fingerprint: &str) -> Result<Vec<u8>, ResultTypes> {
    let mut gpg_ctx = Context::from_protocol(OpenPgp).unwrap();
    let gpg_private_key = gpg_ctx.get_secret_key(key_fingerprint).map_err(|e| e.to_string()).unwrap();
    if !gpg_private_key.can_sign() { return Err(ResultTypes::KeyNoSigAttr); }
    gpg_ctx.add_signer(&gpg_private_key).map_err(|_e| ResultTypes::SigErr)?;

    let mut signature = vec![];
    gpg_ctx.sign(SignMode::Normal, data, &mut signature).map_err(|_e| ResultTypes::SigErr)?;
    Ok(signature)
}

pub fn verify_signature(signature: &Vec<u8>, key_fingerprint: &str, msg: &mut Vec<u8>) -> Result<ResultTypes, ResultTypes> {
    let mut gpg_ctx = Context::from_protocol(OpenPgp).unwrap(); 
    let result = gpg_ctx.verify_opaque(signature, msg).map_err(|_e| ResultTypes::UnknownErr)?;
    let sig = result.signatures().next().expect("Error");

    let is_valid = sig.summary().contains(SignatureSummary::VALID);
    let keys_match = sig.fingerprint()? == key_fingerprint;
    if !is_valid { return Err(ResultTypes::SigInvalid); } 
    if !keys_match { return Err(ResultTypes::KeyMismatch); }
    Ok(ResultTypes::OK)
}
