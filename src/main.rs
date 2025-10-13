use anyhow::Context;
use anyhow::anyhow;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    Client,
    error::SdkError,
    operation::{
        abort_multipart_upload::{AbortMultipartUploadError, AbortMultipartUploadOutput},
        upload_part::UploadPartError,
    },
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};
use std::io::IsTerminal;
use std::ops::Add;
use std::{env, fs};
use std::{io, process::Stdio};

use crate::zfs::Action;
use chacha20::cipher::StreamCipher;
use chrono::TimeDelta;
use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;
use log::debug;
use log::error;
use log::info;
use log::warn;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use tokio::io::AsyncBufReadExt;
use tokio::task::JoinSet;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

mod config;
mod kex;
mod load;
mod zfs;

static CONFIG: Lazy<config::Config> = Lazy::new(|| {
    let cnf = fs::read_to_string(env::var("AWSAVE_CONFIG").unwrap_or("./config.toml".to_string()))
        .expect("Failed to read config");

    toml::from_str(&cnf).expect("Invalid config")
});

fn open_full(dataset: &str, snapshot: &str) -> Result<tokio::process::Child, io::Error> {
    Command::new("sudo")
        .args(["zfs", "send", "-R", &format!("{dataset}@{snapshot}")])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()

    /*Command::new("cat")
    .args(["testfile"])
    .stderr(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()*/
}

fn open_incremental(
    dataset: &str,
    from: &str,
    to: &str,
) -> Result<tokio::process::Child, io::Error> {
    Command::new("sudo")
        .args([
            "zfs",
            "send",
            "-Ri",
            &format!("@{}", from),
            &format!("{dataset}@{to}"),
        ])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
}

pub fn zfs_recv(dataset: &str, snapshot: Option<&str>) -> Result<tokio::process::Child, io::Error> {
    let name = match snapshot {
        Some(snap) => format!("{}@{}", dataset, snap),
        None => dataset.to_owned(),
    };
    Command::new("sudo")
        .arg("zfs")
        .arg("recv")
        .arg(name)
        .stdin(Stdio::piped())
        .spawn()
}

pub async fn read_exact_noerr<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        match reader.read(&mut buf[total..]).await? {
            0 => return Ok(total), // EOF after some data
            n => total += n,
        }
    }

    Ok(total)
}

async fn print_lines<R>(reader: R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut lines = tokio::io::BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        println!("{}", line);
    }

    Ok(())
}

async fn abort_upload(
    client: &Client,
    pc: &UploadConfig,
) -> Result<AbortMultipartUploadOutput, SdkError<AbortMultipartUploadError>> {
    warn!("ABORTING UPLOAD");
    let r = client
        .abort_multipart_upload()
        .bucket(&pc.bucket)
        .key(&pc.key)
        .upload_id(&pc.id)
        .send()
        .await;
    if r.is_err() {
        error!("ABORTING FAILED, {:#?}", pc);
    }

    r
}

async fn encrypt_and_upload<R: AsyncReadExt + Unpin, C: StreamCipher>(
    client: Client,
    pc: UploadConfig,
    mut source: R,
    mut cipher: C,
    expected_size: usize,
) -> anyhow::Result<Vec<u8>> {
    let readsize = if (expected_size / CONFIG.upload_chunk_size) + 200 >= 10000 {
        // Chunks too small
        info!(
            "Chunks are too small, using {} instead",
            expected_size / (10000 - 200)
        );
        expected_size / (10000 - 200)
    } else {
        CONFIG.upload_chunk_size
    };
    let mut buffer = vec![0; readsize];
    let mut hasher = Sha256::new();
    let mut upload_parts = Vec::new();
    let mut part_number = 1;
    let mut total = 0;

    let mut running = JoinSet::new();

    loop {
        let r = read_exact_noerr(&mut source, &mut buffer).await;
        match r {
            Ok(0) => {
                // Read all data
                break;
            }
            Ok(n) => {
                debug!("Read {} bytes", n);
                let mut chunk = buffer[..n].to_vec();
                hasher.update(&chunk);
                cipher.apply_keystream(&mut chunk);

                total += n;
                info!(
                    "Queued chunk #{}, size was {}, total {} MiB, {} %",
                    part_number,
                    n,
                    total / 1024 / 1024,
                    total as f32 / expected_size as f32 * 100.0
                );

                running.spawn(upload_part_outer(
                    client.clone(),
                    pc.clone(),
                    chunk,
                    part_number,
                ));

                part_number += 1;

                if running.len() > CONFIG.max_concurrent {
                    let res = running
                        .join_next()
                        .await
                        .expect("More than max but still empty");

                    match res {
                        Ok(Ok(part)) => {
                            debug!("Part done");
                            upload_parts.push(part)
                        }
                        Ok(Err(e)) => {
                            error!("ERROR, aborting");
                            running.abort_all();
                            return if let Err(ie) = abort_upload(&client, &pc).await {
                                Err(ie)
                                    .context(format!("Failed to upload part #{}", part_number))
                                    .context(e)
                            } else {
                                Err(e.into())
                            };
                        }
                        Err(e) => todo!("Join error {}", e),
                    }
                }
            }
            Err(e) => {
                error!("ERROR, aborting");
                running.abort_all();
                return if let Err(ie) = abort_upload(&client, &pc).await {
                    Err(ie)
                        .context(format!("Failed to read part #{}", part_number))
                        .context(e)
                } else {
                    Err(e.into())
                };
            }
        }
    }

    // All done
    if total == 0 {
        error!("Read 0 bytes");
        return Err(anyhow!("Read 0 bytes"));
    }

    while let Some(jh) = running.join_next().await {
        match jh {
            Ok(Ok(part)) => {
                info!("Part done, {} remaining", running.len());
                upload_parts.push(part)
            }
            Ok(Err(e)) => {
                error!("ERROR, aborting");
                running.abort_all();
                return if let Err(ie) = abort_upload(&client, &pc).await {
                    Err(ie)
                        .context(format!("Failed to upload part #{}", part_number))
                        .context(e)
                } else {
                    Err(e.into())
                };
            }
            Err(e) => todo!("Join error {}", e),
        }
    }

    upload_parts.sort_by_key(|f| f.part_number.expect("part has no part number"));

    let completed_multipart_upload = CompletedMultipartUpload::builder()
        .set_parts(Some(upload_parts))
        .build();

    let cmu = client
        .complete_multipart_upload()
        .bucket(&pc.bucket)
        .key(&pc.key)
        .multipart_upload(completed_multipart_upload)
        .upload_id(&pc.id)
        .send()
        .await;
    if let Err(e) = cmu {
        return if let Err(ie) = abort_upload(&client, &pc).await {
            Err(ie).context("Failed to finalize upload").context(e)
        } else {
            Err(e.into())
        };
    }

    Ok(hasher.finalize().to_vec())
}

#[derive(Debug, Clone)]
struct UploadConfig {
    key: String,
    bucket: String,
    id: String,
}

async fn upload_part_outer(
    client: Client,
    pc: UploadConfig,
    data: Vec<u8>,
    part_number: i32,
) -> Result<CompletedPart, SdkError<UploadPartError>> {
    upload_part(&client, &pc, data, part_number).await
}

async fn upload_part(
    client: &Client,
    pc: &UploadConfig,
    data: Vec<u8>,
    part_number: i32,
) -> Result<CompletedPart, SdkError<UploadPartError>> {
    let data = ByteStream::from(data);
    let upload_part_res = client
        .upload_part()
        .key(&pc.key)
        .bucket(&pc.bucket)
        .upload_id(&pc.id)
        .body(data)
        .part_number(part_number)
        .send()
        .await?;

    Ok(CompletedPart::builder()
        .e_tag(upload_part_res.e_tag.unwrap_or_default())
        .part_number(part_number)
        .build())
}

async fn ensure_consistency(client: &Client, desired_datasets: &[&str]) -> anyhow::Result<()> {
    let snaps = zfs::get_current_state(client, &CONFIG.bucket).await?;
    let snaps_s: Vec<String> = snaps.iter().map(|s| s.to_string()).collect();
    debug!("Current snapshots:\n{}", snaps_s.join("\n"));

    let now = chrono::Utc::now();

    let state = zfs::get_current_state(client, &CONFIG.bucket).await?;
    let actions = zfs::check_state(desired_datasets, &state, now);

    if actions.is_empty() {
        info!("Nothing to do!");
        return Ok(());
    }

    if io::stderr().is_terminal()
        && !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "These actions are about to be performed, continue?\n{}",
                actions
                    .iter()
                    .map(Action::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
            .default(true)
            .interact()?
    {
        return Ok(());
    }

    for act in actions {
        let res = act.perform_aws(client).await?;

        match res {
            zfs::ActionPerformResult::Delete(_delete_object_output) => todo!(),
            zfs::ActionPerformResult::CreateFull(upload_result)
            | zfs::ActionPerformResult::CreateIncremental(upload_result) => {
                let di = kex::DecryptionInfo::encrypt(upload_result)
                    .context("Uploaded backup, but key could not be encrypted")?;
                di.save_to_aws(client).await.with_context(|| format!("Uploaded backup. but key could not be uploaded. Filename: {}, hash: {}, keyiv: {}", &di.filename, hex::encode(&di.hash), hex::encode(&di.key_iv)))?;

                info!(
                    "Upload of {} successful, hash is {}, key_iv is {}",
                    di.filename,
                    hex::encode(&di.hash),
                    hex::encode(&di.key_iv)
                );
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    colog::init();
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let client = Client::new(&config);

    let desired_datasets: Vec<&str> = CONFIG.desired_datasets.iter().map(|s| s.as_str()).collect();

    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && args[1] == "recover" {
        if let Err(e) = load::full_recover_all::<chacha20::ChaCha20>(&client).await {
            error!("Error encountered while restoring: {}\n{:?}", e, e.source());
        }
    } else if args.len() > 1 {
        error!(
            "Too many arguments: {}, use \"{} recover\" to start recovery process",
            args.len(),
            args[0]
        );
        return Err(anyhow::anyhow!("Too many arguments"));
    } else if let Err(r) = ensure_consistency(&client, &desired_datasets).await {
        error!("Error encountered while ensuring consistency: {}", r);
    }

    info!("Cleaning up...");

    let resp = client
        .list_multipart_uploads()
        .bucket(&CONFIG.bucket)
        .send()
        .await;

    match resp {
        Ok(ls) => {
            for b in ls.uploads() {
                let pc = UploadConfig {
                    key: b.key().expect("Missing key").to_string(),
                    bucket: CONFIG.bucket.clone(),
                    id: b.upload_id().expect("No upload id").to_string(),
                };

                abort_upload(&client, &pc).await?;
            }
        }
        Err(e) => {
            error!("Failed to get: {}", e.into_service_error());
        }
    };

    Ok(())
}
