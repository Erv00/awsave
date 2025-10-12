use std::{fmt::Write, io::IsTerminal};

use anyhow::{Context, anyhow};
use aws_sdk_s3::Client;
use chacha20::cipher::{IvSizeUser, KeySizeUser, StreamCipher};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use log::{debug, error, info, warn};
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
    let state = crate::zfs::get_current_state(client, &crate::CONFIG.bucket).await?;
    let mut state: Vec<Snapshot> = state.into_iter().filter(|s| s.dataset() == ds).collect();
    state.sort_by_key(|s| *s.date());

    if state.is_empty() {
        error!("No snapshot for dataset '{ds}'");
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
                warn!("{} needs to be restored", s.aws_key());
            }
            Some(AvailabilityInfo::RestoreInProgress) => {
                abort = true;
                warn!("{} is still restoring, be patient", s.aws_key());
            }
            Some(AvailabilityInfo::Available) => (),
        }
    }

    if abort {
        error!("Not all data is available, terminating");
        return Err(anyhow::anyhow!("Not all data is available"));
    }

    // TODO: Confirm
    info!("About to download {} chunks", needed.len());

    for s in needed {
        let res = client
            .get_object()
            .bucket(&crate::CONFIG.bucket)
            .key(format!("{}.key", s.aws_key()))
            .send()
            .await?;
        let key = res.body.collect().await?;
        let key: DecryptionInfo = serde_json::from_slice(&key.into_bytes())?;
        let (enckey, iv) = key.decrypt("master-key.pem")?;

        info!("Decryption done, expected hash: {}", hex::encode(&key.hash));

        let mut cipher = C::new(&enckey.into(), &iv.into());
        let mut hasher = Sha256::new();
        let mut res = client
            .get_object()
            .bucket(&crate::CONFIG.bucket)
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
        let size = res.content_length;
        let mut total = 0;

        let pb = ProgressBar::new(size.unwrap_or(0) as u64);

        if size.is_some() {
            pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
            .progress_chars("#>-"));
        } else {
            pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes} (???s) {msg}")
            .unwrap()
            .progress_chars("#>-"));
        }

        while let Some(bytes) = res.body.try_next().await? {
            let mut bytes = bytes.to_vec();
            cipher.apply_keystream(&mut bytes);
            hasher.update(&bytes);
            p.write_all(&bytes).await?;
            debug!("Consumed {} bytes", bytes.len())
            total += bytes.len();
            if let Some(size) = size {
                info!(
                    "Consumed {} bytes, {} %",
                    bytes.len(),
                    total as f32 / size as f32 * 100.0
                );
            } else {
                info!("Consumed {} bytes, ??? %", bytes.len());
            }
            if std::io::stderr().is_terminal() {
                pb.set_position(total as u64);
            }
        }

        let hash = hasher.finalize().to_vec();

        let res = zfs.wait().await?;
        if !res.success() {
            return Err(anyhow!("Failed to feed to zfs recv: {:?}", res.code()));
        }

        if hash != key.hash {
            pb.finish_with_message(format!("HASH MISMATCH expected {}, got {}",
                hex::encode(&key.hash),
                hex::encode(&hash)));
            return Err(anyhow!(
                "HASH MISMATCH expected {}, got {}",
                hex::encode(&key.hash),
                hex::encode(&hash)
            ));
        }

        pb.finish_with_message(format!("Succesfully restored {}", &key.filename));
        info!("Succesfully restored {}", &key.filename);
    }

    info!("SUCCESS! All data restored!");

    Ok(())
}
