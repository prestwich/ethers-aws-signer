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
use tracing::{debug, instrument, trace};
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
    Spki(spki::der::Error),
    #[error("{0}")]
    Other(String),
}

impl From<String> for AwsSignerError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<spki::der::Error> for AwsSignerError {
    fn from(e: spki::der::Error) -> Self {
        Self::Spki(e)
    }
}

#[instrument(err, skip(kms))]
async fn request_get_pubkey(
    kms: &KmsClient,
    key_id: String,
) -> Result<rusoto_kms::GetPublicKeyResponse, RusotoError<GetPublicKeyError>> {
    debug!("Dispatching get_public_key");

    let req = GetPublicKeyRequest {
        grant_tokens: None,
        key_id,
    };
    trace!("{:?}", &req);
    let resp = kms.get_public_key(req).await;
    trace!("{:?}", &resp);
    resp
}

#[instrument(err, skip(kms))]
async fn request_sign_digest<T>(
    kms: &KmsClient,
    key_id: T,
    digest: [u8; 32],
) -> Result<SignResponse, RusotoError<SignError>>
where
    T: AsRef<str> + std::fmt::Debug,
{
    debug!("Dispatching sign");
    let req = SignRequest {
        grant_tokens: None,
        key_id: key_id.as_ref().to_owned(),
        message: digest.to_vec().into(),
        message_type: Some("DIGEST".to_owned()),
        signing_algorithm: "ECDSA_SHA_256".to_owned(),
    };
    trace!("{:?}", &req);
    let resp = kms.sign(req).await;
    trace!("{:?}", &resp);
    resp
}

impl<'a> AwsSigner<'a> {
    #[instrument(err, skip(kms))]
    pub async fn new<T>(
        kms: &'a KmsClient,
        key_id: T,
        chain_id: u64,
    ) -> Result<AwsSigner<'a>, AwsSignerError>
    where
        T: AsRef<str> + std::fmt::Debug,
    {
        let key_id = key_id.as_ref().to_owned();
        let pubkey = request_get_pubkey(kms, key_id.clone())
            .await
            .map(utils::decode_pubkey)??;
        let address = verifying_key_to_address(&pubkey);

        debug!(
            "Instantiated AWS signer with pubkey 0x{} and address 0x{}",
            hex::encode(&pubkey.to_bytes()),
            hex::encode(&address)
        );

        Ok(Self {
            kms,
            chain_id,
            key_id,
            pubkey,
            address,
        })
    }

    pub async fn get_pubkey_for_key<T>(&self, key_id: T) -> Result<VerifyingKey, AwsSignerError>
    where
        T: AsRef<str> + std::fmt::Debug,
    {
        Ok(request_get_pubkey(&self.kms, key_id.as_ref().to_owned())
            .await
            .map(utils::decode_pubkey)??)
    }

    pub async fn get_pubkey(&self) -> Result<VerifyingKey, AwsSignerError> {
        self.get_pubkey_for_key(&self.key_id).await
    }

    pub async fn sign_digest_with_key<T>(
        &self,
        key_id: T,
        digest: [u8; 32],
    ) -> Result<KSig, AwsSignerError>
    where
        T: AsRef<str> + std::fmt::Debug,
    {
        Ok(request_sign_digest(&self.kms, key_id, digest)
            .await
            .map(utils::decode_signature)??)
    }

    pub async fn sign_digest(&self, digest: [u8; 32]) -> Result<KSig, AwsSignerError> {
        self.sign_digest_with_key(self.key_id.clone(), digest).await
    }

    #[instrument(err)]
    async fn sign_digest_with_eip155(&self, digest: H256) -> Result<EthSig, AwsSignerError> {
        let sig = self.sign_digest(digest.into()).await?;

        let sig = RSig::from_trial_recovery(&self.pubkey, digest.as_ref(), &sig)
            .expect("just produced it, must be good");

        let mut sig = rsig_to_ethsig(&sig);
        apply_eip155(&mut sig, self.chain_id);
        trace!("{}", sig.v);
        Ok(sig)
    }
}

#[async_trait::async_trait]
impl<'a> ethers::prelude::Signer for AwsSigner<'a> {
    type Error = AwsSignerError;

    #[instrument(err, skip(message))]
    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<EthSig, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);
        trace!("{:?}", message_hash);
        trace!("{:?}", message);

        self.sign_digest_with_eip155(message_hash).await
    }

    #[instrument(err)]
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
    use rusoto_core::{
        credential::{EnvironmentProvider, StaticProvider},
        Client, HttpClient, Region,
    };

    use super::*;

    #[allow(dead_code)]
    fn local_client() -> KmsClient {
        let access_key = "".to_owned();
        let secret_access_key = "".to_owned();

        let client = Client::new_with(
            StaticProvider::new(access_key, secret_access_key, None, None),
            HttpClient::new().unwrap(),
        );
        KmsClient::new_with_client(
            client,
            Region::Custom {
                name: "local".to_owned(),
                endpoint: "http://localhost:8000".to_owned(),
            },
        )
    }

    fn env_client() -> KmsClient {
        let client = Client::new_with(EnvironmentProvider::default(), HttpClient::new().unwrap());
        KmsClient::new_with_client(client, Region::UsWest1)
    }

    #[tokio::test]
    async fn it_signs_messages() {
        let chain_id = 1;
        let key_id = "".to_owned();
        let client = env_client();
        let signer = AwsSigner::new(&client, key_id, chain_id).await.unwrap();

        dbg!(&signer);

        let message = vec![0, 1, 2, 3];

        let sig = signer.sign_message(&message).await.unwrap();
        sig.verify(message, signer.address).expect("valid sig");
    }
}
