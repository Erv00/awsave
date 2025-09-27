use anyhow::Context;
use aws_sdk_s3::{
    error::SdkError, operation::put_object::{PutObjectError, PutObjectOutput}, primitives::ByteStream, Client
};
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Serialize, Serializer};
use sha2::Sha256;

const MASTER_KEY_STR: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtsQsUV8QpqrygsY+2+JC
Q6Fw8/omM71IM2N/R8pPbzbgOl0p78MZGsgPOQ2HSznjD0FPzsH8oO2B5Uftws04
LHb2HJAYlz25+lN5cqfHAfa3fgmC38FfwBkn7l582UtPWZ/wcBOnyCgb3yLcvJrX
yrt8QxHJgvWO23ITrUVYszImbXQ67YGS0YhMrbixRzmo2tpm3JcIBtnHrEUMsT0N
fFdfsZhTT8YbxBvA8FdODgEwx7u/vf3J9qbi4+Kv8cvqyJuleIRSjVXPsIMnoejI
n04APPKIjpMyQdnWlby7rNyQtE4+CV+jcFjqJbE/Xilcvqxt6DirjFCvYeKYl1uH
LwIDAQAB
-----END PUBLIC KEY-----";

pub fn generate_key() -> ([u8; 32], [u8; 12]) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 32];
    let mut iv = [0; 12];

    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    (key, iv)
}

fn serialize_hex<S>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
    s.collect_str(&hex::encode(v))
}

#[derive(Serialize)]
pub struct DecryptionInfo {
    pub filename: String,
    #[serde(serialize_with = "serialize_hex")]
    pub hash: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    pub key_iv: Vec<u8>,
}

impl DecryptionInfo {
    pub fn encrypt(res: crate::zfs::UploadResult) -> anyhow::Result<DecryptionInfo> {
        let mk = RsaPublicKey::from_public_key_pem(MASTER_KEY_STR).expect("Inavild master key");
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<Sha256>();

        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&res.key);
        data.extend_from_slice(&res.iv);

        let enc_data = mk.encrypt(&mut rng, padding, &data[..])?;

        Ok(DecryptionInfo {
            filename: res.filename.clone(),
            hash: res.hash.clone(),
            key_iv: enc_data,
        })
    }

    pub async fn save_to_aws(
        &self,
        client: &Client,
    ) -> anyhow::Result<PutObjectOutput> {
        let b = serde_json::to_string_pretty(&self)?;
        let b = ByteStream::from(b.bytes().collect::<Vec<_>>());
        client
            .put_object()
            .bucket(crate::BUCKET)
            .key(format!("{}.key", &self.filename))
            .body(b)
            .send()
            .await.context("Failed to upload key")
    }
}
