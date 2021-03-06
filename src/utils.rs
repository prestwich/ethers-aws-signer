use std::convert::TryFrom;

use ethers::{
    core::k256::{
        ecdsa::{recoverable::Signature as RSig, Signature as KSig, VerifyingKey},
        elliptic_curve::sec1::ToEncodedPoint,
        FieldBytes,
    },
    prelude::{Address, Signature as EthSig, H256},
    utils::keccak256,
};
use k256::ecdsa::recoverable::Id;
use rusoto_kms::{GetPublicKeyResponse, SignResponse};

use crate::AwsSignerError;

// pub(crate) fn ethsig_to_rsig(sig: &EthSig) -> RSig {
//     let recovery_id = ((sig.v % 2) as u8).try_into().unwrap();
//     let sig = ethsig_to_ksig(sig);
//     RSig::new(&sig, recovery_id).unwrap()
// }

// pub(crate) fn ethsig_to_ksig(sig: &EthSig) -> KSig {
//     let r: [u8; 32] = sig.r.into();
//     let s: [u8; 32] = sig.s.into();
//     KSig::from_scalars(r, s).unwrap()
// }

pub(crate) fn rsig_to_ethsig(sig: &RSig) -> EthSig {
    let v: u8 = sig.recovery_id().into();
    let v = (v + 27) as u64;
    let r_bytes: FieldBytes = sig.r().into();
    let s_bytes: FieldBytes = sig.s().into();
    let r = H256::from_slice(&r_bytes.as_slice());
    let s = H256::from_slice(&s_bytes.as_slice());
    EthSig { r, s, v }
}

fn check_candidate(sig: &RSig, digest: [u8; 32], vk: &VerifyingKey) -> bool {
    if let Ok(key) = sig.recover_verify_key_from_digest_bytes(digest.as_ref().into()) {
        key == *vk
    } else {
        false
    }
}

pub(crate) fn rsig_from_digest_bytes_trial_recovery(
    sig: &KSig,
    digest: [u8; 32],
    vk: &VerifyingKey,
) -> RSig {
    let sig_0 = RSig::new(sig, Id::new(0).unwrap()).unwrap();
    let sig_1 = RSig::new(sig, Id::new(1).unwrap()).unwrap();

    if check_candidate(&sig_0, digest, vk) {
        sig_0
    } else if check_candidate(&sig_1, digest, vk) {
        sig_1
    } else {
        panic!("bad sig");
    }
}

pub(crate) fn apply_eip155(sig: &mut EthSig, chain_id: u64) {
    let v = (chain_id * 2 + 35) + ((sig.v - 1) % 2);
    sig.v = v;
}

pub(crate) fn verifying_key_to_address(key: &VerifyingKey) -> Address {
    // false for uncompressed
    let uncompressed_pub_key = key.to_encoded_point(false);
    let public_key = uncompressed_pub_key.to_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

pub(crate) fn decode_pubkey(resp: GetPublicKeyResponse) -> Result<VerifyingKey, AwsSignerError> {
    let raw = resp
        .public_key
        .ok_or_else(|| AwsSignerError::from("Pubkey not found in response".to_owned()))?;

    let spk = spki::SubjectPublicKeyInfo::try_from(raw.as_ref())?;
    let key = VerifyingKey::from_sec1_bytes(&spk.subject_public_key)?;

    Ok(key)
}

pub(crate) fn decode_signature(resp: SignResponse) -> Result<KSig, AwsSignerError> {
    let raw = resp
        .signature
        .ok_or_else(|| AwsSignerError::from("Signature not found in response".to_owned()))?;

    let mut sig = KSig::from_asn1(&raw)?;
    sig.normalize_s()?;
    Ok(sig)
}
