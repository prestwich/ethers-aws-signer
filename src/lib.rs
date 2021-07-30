use ethers::{
    core::k256::ecdsa::{
        recoverable::Signature as RSig, Error as K256Error, Signature as KSig, VerifyingKey,
    },
    prelude::{Address, Signature as EthSig, H256},
    utils::hash_message,
};
use rusoto_core::RusotoError;
use rusoto_kms::{
    GetPublicKeyError, GetPublicKeyRequest, Kms, KmsClient, SignError, SignRequest, SignResponse,
};
use utils::{apply_eip155, rsig_to_ethsig, verifying_key_to_address};

mod utils;

#[derive(Clone)]
pub struct AwsSigner<'a> {
    kms: &'a rusoto_kms::KmsClient,
    chain_id: u64,
    key_id: String,
    pubkey: VerifyingKey,
    address: Address,
}

impl<'a> std::fmt::Debug for AwsSigner<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSigner")
            .field("key_id", &self.key_id)
            .field("chain_id", &self.chain_id)
            .field("pubkey", &self.pubkey)
            .field("address", &self.address)
            .finish()
    }
}

impl<'a> std::fmt::Display for AwsSigner<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AwsSigner {{ address: {}, chain_id: {}, key_id: {} }}",
            self.address, self.chain_id, self.key_id
        )
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AwsSignerError {
    #[error("{0}")]
    SignError(#[from] RusotoError<SignError>),
    #[error("{0}")]
    GetPublicKeyError(#[from] RusotoError<GetPublicKeyError>),
    #[error("No default key. Must provide a default key to use this method.")]
    NoDefaultKey,
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    K256(#[from] K256Error),
    #[error("{0}")]
    Other(String),
}

impl From<String> for AwsSignerError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

async fn request_get_pubkey(
    kms: &KmsClient,
    key_id: String,
) -> Result<rusoto_kms::GetPublicKeyResponse, RusotoError<GetPublicKeyError>> {
    let req = GetPublicKeyRequest {
        grant_tokens: None,
        key_id,
    };
    kms.get_public_key(req).await
}

async fn request_sign_digest(
    kms: &KmsClient,
    key_id: String,
    digest: [u8; 32],
) -> Result<SignResponse, RusotoError<SignError>> {
    let req = SignRequest {
        grant_tokens: None,
        key_id,
        message: digest.to_vec().into(),
        message_type: Some("DIGEST".to_owned()),
        signing_algorithm: "ECDSA_SHA_256".to_owned(),
    };

    kms.sign(req).await
}

impl<'a> AwsSigner<'a> {
    pub async fn new(
        kms: &'a KmsClient,
        key_id: String,
        chain_id: u64,
    ) -> Result<AwsSigner<'a>, AwsSignerError> {
        let pubkey = request_get_pubkey(kms, key_id.clone())
            .await
            .map(utils::decode_pubkey)??;
        let address = verifying_key_to_address(&pubkey);
        Ok(Self {
            kms,
            chain_id,
            key_id,
            pubkey,
            address,
        })
    }

    pub async fn get_pubkey_for_key(&self, key_id: String) -> Result<VerifyingKey, AwsSignerError> {
        Ok(request_get_pubkey(&self.kms, key_id)
            .await
            .map(utils::decode_pubkey)??)
    }

    pub async fn get_pubkey(&self) -> Result<VerifyingKey, AwsSignerError> {
        self.get_pubkey_for_key(self.key_id.clone()).await
    }

    pub async fn sign_digest_with_key(
        &self,
        key_id: String,
        digest: [u8; 32],
    ) -> Result<KSig, AwsSignerError> {
        Ok(request_sign_digest(&self.kms, key_id, digest)
            .await
            .map(utils::decode_signature)??)
    }

    pub async fn sign_digest(&self, digest: [u8; 32]) -> Result<KSig, AwsSignerError> {
        self.sign_digest_with_key(self.key_id.clone(), digest).await
    }

    async fn sign_digest_with_eip155(&self, digest: H256) -> Result<EthSig, AwsSignerError> {
        let sig = self.sign_digest(digest.into()).await?;

        let sig = RSig::from_trial_recovery(&self.pubkey, digest.as_ref(), &sig)
            .expect("just produced it, must be good");

        let mut sig = rsig_to_ethsig(&sig);
        apply_eip155(&mut sig, self.chain_id);
        Ok(sig)
    }
}

#[async_trait::async_trait]
impl<'a> ethers::prelude::Signer for AwsSigner<'a> {
    type Error = AwsSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<EthSig, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);

        self.sign_digest_with_eip155(message_hash).await
    }

    async fn sign_transaction(
        &self,
        tx: &ethers::prelude::TransactionRequest,
    ) -> Result<EthSig, Self::Error> {
        let sighash = tx.sighash(Some(self.chain_id));
        self.sign_digest_with_eip155(sighash).await
    }

    fn address(&self) -> ethers::prelude::Address {
        self.address
    }
}

#[cfg(test)]
mod tests {
    use ethers::prelude::Signer;
    use rusoto_core::{credential::EnvironmentProvider, Client, HttpClient, Region};

    use super::*;

    #[tokio::test]
    async fn it_signs_messages() {
        let chain_id = 1;

        let client = Client::new_with(EnvironmentProvider::default(), HttpClient::new().unwrap());
        let client = KmsClient::new_with_client(client, Region::UsWest1);
        let signer = AwsSigner::new(&client, "".to_owned(), chain_id)
            .await
            .unwrap();

        dbg!(&signer);

        let message = vec![0, 1, 2, 3];

        let sig = signer.sign_message(&message).await.unwrap();
        sig.verify(message, signer.address).expect("valid sig");
    }
}
