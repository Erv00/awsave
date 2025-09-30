use std::path::Path;

use anyhow::{Context, anyhow};
use aws_sdk_s3::{
    Client,
    operation::put_object::PutObjectOutput,
    primitives::ByteStream,
};
use rand::RngCore;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MASTER_KEY_STR: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtTgbzg99TMWA6EsQJ8X1
Jiqiju3fSz489Z4h8FOgIaVSCUwgL9HCKSLf7bnn3caz1YPKHF+59KQyXg0f5ma3
UbV150OBHLNNM2jPQrxZhpmLFQPTHlONMu/W1g/BNvoQziDi2MZZon/Td0mT0oyR
ffve8pNvIgydMqv0BY25OJ+0jaa3MlmfSFepSOO00bMfHwA2BSLMQSfOL5kCo36e
uryQaxTa65YUXhlB0iuRe9MCR425rjL+vQ8vJp02LGVx6K5nyV0JwPfMvJHJC0Lm
i2CHIuvWlF0TIAePXGENO8yGcRztzzMy8QlPvBL0RQqv6nd3EPAuwuvx3v+nBDF3
zSOu9boAeYuxY7tBOnS+dop7hqY5L1oBuSmQXYgUyGdWI61Q6/sW/c7QkF5B16lZ
2I309Ermxm99rSqoIuN9Zxan/dorwXuh42xO1nPJV5aI+0LNEOrgIQdEDUDB9cNQ
aW8cdfBwswOPQhf2HkfFVsuMRn5A9YBd014nPuM+oHBrSjCx6si1OPyBCmUhERr2
R+pWReGmvvg9Kwnb7udNHDGVO6ASpUBCpOpX50AuHSISsEiK/U5n2Iku6m6FOzfN
Zx8QLor/UhZ2fgForcVwwH4c6rHrPnGB2dcUbzO7OwODvWohUzGMh6xfX7IGR1Jl
KYUcsw+O09sliWURRet8IGkCAwEAAQ==
-----END PUBLIC KEY-----";

pub fn generate_key() -> ([u8; 32], [u8; 12]) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 32];
    let mut iv = [0; 12];

    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    (key, iv)
}

mod prettyhex {
    use serde::{Deserializer, Serializer, de};

    pub(super) fn serialize<S>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.collect_str(&hex::encode(v))
    }

    pub(super) fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = de::Deserialize::deserialize(d)?;
        let a = hex::decode(s).map_err(de::Error::custom)?;
        Ok(a)
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionInfo {
    pub filename: String,
    #[serde(with = "prettyhex")]
    pub hash: Vec<u8>,
    #[serde(with = "prettyhex")]
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

    pub fn decrypt(&self, keypem: impl AsRef<Path>) -> anyhow::Result<([u8; 32], [u8; 12])> {
        let key = RsaPrivateKey::read_pkcs8_pem_file(keypem)?;
        let padding = Oaep::new::<Sha256>();

        let key_iv = key.decrypt(padding, &self.key_iv)?;
        if key_iv.len() != 32 + 12 {
            return Err(anyhow!("Keylength incorrect"));
        }

        let (key, iv) = key_iv.split_at(32);

        Ok((key.try_into().unwrap(), iv.try_into().unwrap()))
    }

    pub async fn save_to_aws(&self, client: &Client) -> anyhow::Result<PutObjectOutput> {
        let b = serde_json::to_string_pretty(&self)?;
        let b = ByteStream::from(b.bytes().collect::<Vec<_>>());
        client
            .put_object()
            .bucket(crate::BUCKET)
            .key(format!("{}.key", &self.filename))
            .body(b)
            .send()
            .await
            .context("Failed to upload key")
    }
}
