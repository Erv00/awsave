use std::collections::HashSet;
use std::fmt::Write;

use anyhow::{Context, anyhow};
use aws_sdk_s3::Client;
use chacha20::cipher::{IvSizeUser, KeySizeUser, StreamCipher};
use dialoguer::{Confirm, MultiSelect, theme::ColorfulTheme};
use indicatif::{HumanBytes, HumanCount, MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use log::{error, warn};
use sha2::{Digest, Sha256, digest::generic_array::GenericArray};

use crate::{
    kex::DecryptionInfo,
    zfs::{AvailabilityInfo, Snapshot},
};

pub async fn full_recover_all<C: StreamCipher + chacha20::cipher::KeyIvInit>(
    client: &Client,
) -> anyhow::Result<()>
where
    GenericArray<u8, <C as KeySizeUser>::KeySize>: From<[u8; 32]>,
    GenericArray<u8, <C as IvSizeUser>::IvSize>: From<[u8; 12]>,
{
    let state = crate::zfs::get_current_state(client, &crate::CONFIG.bucket).await?;
    let mut available_datasets = HashSet::new();

    for snap in state {
        available_datasets.insert(snap.dataset().to_owned());
    }

    let available_datasets: Vec<String> = available_datasets.into_iter().collect();

    let desired_datasets = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Which datasets to recover?")
        .items_checked(available_datasets.iter().map(|v| (v, true)))
        .interact()?;

    if desired_datasets.is_empty() {
        return Ok(());
    }

    let mp = MultiProgress::new();
    let pb = mp.add(ProgressBar::new(desired_datasets.len() as u64));
    pb.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
    )?);
    pb.set_position(0);

    for desired_dataset in desired_datasets {
        let ds = &available_datasets[desired_dataset];

        full_recover_one::<C>(client, ds, Some(&mp)).await?;
        pb.inc(1);
    }

    pb.finish_with_message("All dataset recovered");

    Ok(())
}

pub async fn full_recover_one<C: StreamCipher + chacha20::cipher::KeyIvInit>(
    client: &Client,
    ds: &str,
    bars: Option<&MultiProgress>,
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

    let total_size = needed.iter().fold(0, |acc, x| acc + x.size().unwrap_or(0));

    // Confirm
    if bars.is_none()
        && !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "About to download {} snapshots, {} total, continue?",
                HumanCount(needed.len() as u64),
                HumanBytes(total_size as u64)
            ))
            .default(true)
            .interact()?
    {
        return Ok(());
    }

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

        //info!("Decryption done, expected hash: {}", hex::encode(&key.hash));

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

        let pb = if let Some(bars) = bars {
            bars.add(ProgressBar::new(size.unwrap_or(0) as u64))
        } else {
            ProgressBar::new(size.unwrap_or(0) as u64)
        };

        if size.is_some() {
            pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")?
            .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
            .progress_chars("#>-"));
        } else {
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] {bytes} (???s) {msg}",
                )?
                .progress_chars("#>-"),
            );
        }

        while let Some(bytes) = res.body.try_next().await? {
            let mut bytes = bytes.to_vec();
            cipher.apply_keystream(&mut bytes);
            hasher.update(&bytes);
            p.write_all(&bytes).await?;
            debug!("Consumed {} bytes", bytes.len())
            total += bytes.len();
            pb.set_position(total as u64);
        }

        let hash = hasher.finalize().to_vec();

        let res = zfs.wait().await?;
        if !res.success() {
            return Err(anyhow!("Failed to feed to zfs recv: {:?}", res.code()));
        }

        if hash != key.hash {
            pb.finish_with_message(format!(
                "HASH MISMATCH expected {}, got {}",
                hex::encode(&key.hash),
                hex::encode(&hash)
            ));
            return Err(anyhow!(
                "HASH MISMATCH expected {}, got {}",
                hex::encode(&key.hash),
                hex::encode(&hash)
            ));
        }

        pb.finish_with_message(format!("Successfully restored {}", &key.filename));
        //info!("Successfully restored {}", &key.filename);
    }

    //info!("SUCCESS! All data restored!");

    Ok(())
}
