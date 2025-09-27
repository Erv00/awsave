use anyhow::{Context, anyhow};
use aws_sdk_s3::Client;
use chacha20::cipher::{IvSizeUser, KeySizeUser, StreamCipher};
use sha2::{Digest, Sha256, digest::generic_array::GenericArray};
use tokio::io::AsyncWriteExt;

use crate::{
    kex::DecryptionInfo,
    zfs::{AvailabilityInfo, Snapshot},
};

pub async fn full_recover<C: StreamCipher + chacha20::cipher::KeyIvInit>(
    client: &Client,
    ds: &str,
) -> anyhow::Result<()>
where
    GenericArray<u8, <C as KeySizeUser>::KeySize>: From<[u8; 32]>,
    GenericArray<u8, <C as IvSizeUser>::IvSize>: From<[u8; 12]>,
{
    let state = crate::zfs::get_current_state(client, crate::BUCKET).await?;
    println!(
        "Got {} states {} {} {}",
        state.len(),
        state[0].dataset(),
        ds,
        state[0].dataset() == ds
    );
    let mut state: Vec<Snapshot> = state.into_iter().filter(|s| s.dataset() == ds).collect();
    println!(
        "Got2 {} states {} {} {}",
        state.len(),
        state[0].dataset(),
        ds,
        state[0].dataset() == ds
    );
    state.sort_by_key(|s| *s.date());

    if state.len() == 0 {
        println!("No snapshot for dataset '{ds}'");
        return Err(anyhow::anyhow!("No snapshot data"));
    }

    let mut iter = state.into_iter();
    let e = iter
        .rfind(|s| match s {
            Snapshot::Full(_) => true,
            Snapshot::Incremental(_) => false,
        })
        .context("No full backup found")?;

    let mut needed: Vec<Snapshot> = Vec::new();
    needed.push(e);
    needed.extend(iter);
    let mut abort = false;

    for s in &needed {
        match s.availability() {
            None => panic!("{} has unknown availability", s.aws_key()),
            Some(AvailabilityInfo::CanRestore) => {
                abort = true;
                println!("{} needs to be restored", s.aws_key());
            }
            Some(AvailabilityInfo::RestoreInProgress) => {
                abort = true;
                println!("{} is still restoring, be patient", s.aws_key());
            }
            Some(AvailabilityInfo::Available) => (),
        }
    }

    if abort {
        println!("Not all data is available, terminating");
        return Err(anyhow::anyhow!("Not all data is available"));
    }

    // TODO: Confirm
    println!("About to download {} chunks", needed.len());

    for s in needed {
        let res = client
            .get_object()
            .bucket(crate::BUCKET)
            .key(format!("{}.key", s.aws_key()))
            .send()
            .await?;
        let key = res.body.collect().await?;
        let key: DecryptionInfo = serde_json::from_slice(&key.into_bytes())?;
        let (enckey, iv) = key.decrypt("master-key.pem")?;

        let mut cipher = C::new(&enckey.into(), &iv.into());
        let mut hasher = Sha256::new();
        let mut res = client
            .get_object()
            .bucket(crate::BUCKET)
            .key(s.aws_key())
            .send()
            .await?;

        let mut zfs = match &s {
            Snapshot::Full(full_snapshot) => crate::zfs_recv(&full_snapshot.dataset, None),
            Snapshot::Incremental(incremental_snapshot) => crate::zfs_recv(
                &incremental_snapshot.dataset,
                Some(&incremental_snapshot.name),
            ),
        }?;

        let mut p = zfs.stdin.take().unwrap();

        while let Some(bytes) = res.body.try_next().await? {
            let mut bytes = bytes.to_vec();
            cipher.apply_keystream(&mut bytes);
            hasher.update(&bytes);
            p.write_all(&bytes).await?;
            println!("Consumed {} bytes", bytes.len())
        }

        let hash = hasher.finalize().to_vec();

        let res = zfs.wait().await?;
        if !res.success() {
            return Err(anyhow!("Failed to feed to zfs recv: {:?}", res.code()));
        }

        if hash != key.hash {
            return Err(anyhow!(
                "HASH MISMATCH expected {}, got {}",
                hex::encode(&key.hash),
                hex::encode(&hash)
            ));
        }

        println!("Succesfully restored {}", &key.filename);
    }

    println!("SUCCESS!\nAll data restored!");

    Ok(())
}
