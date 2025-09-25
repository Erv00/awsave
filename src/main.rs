use std::sync::Arc;
use std::{io, process::Stdio};

use anyhow::Context;
use anyhow::anyhow;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{
    self as s3, Client,
    error::SdkError,
    operation::{
        abort_multipart_upload::{AbortMultipartUploadError, AbortMultipartUploadOutput},
        create_multipart_upload::CreateMultipartUploadOutput,
        upload_part::UploadPartError,
    },
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

mod zfs;

const UPLOAD_CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
const MAX_CONCURRENT: usize = 32;

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
    println!("ABORTING UPLOAD");
    let r = client
        .abort_multipart_upload()
        .bucket(&pc.bucket)
        .key(&pc.key)
        .upload_id(&pc.id)
        .send()
        .await;
    if r.is_err() {
        println!("ABORTING FAILED, {:#?}", pc);
    }

    r
}

async fn encypt_and_upload<R: AsyncReadExt + Unpin, C: StreamCipher>(
    client: Arc<Mutex<Client>>,
    pc: UploadConfig,
    mut source: R,
    mut cipher: C,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(UPLOAD_CHUNK_SIZE);
    buffer.resize(UPLOAD_CHUNK_SIZE, 0);
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
                println!("Read {} bytes", n);
                let mut chunk = buffer[..n].to_vec();
                cipher.apply_keystream(&mut chunk);
                hasher.update(&chunk);

                total += n;
                println!(
                    "Queued chunk #{}, size was {}, total {} MiB, running {}",
                    part_number,
                    n,
                    total / 1024 / 1024,
                    running.len()
                );

                running.spawn(upload_part_outer(
                    client.clone(),
                    pc.clone(),
                    chunk,
                    part_number,
                ));

                part_number = part_number + 1;

                if running.len() > MAX_CONCURRENT {
                    let res = running
                        .join_next()
                        .await
                        .expect("More than max but still empty");

                    match res {
                        Ok(Ok(part)) => upload_parts.push(part),
                        Ok(Err(e)) => {
                            println!("ERROR, aborting");
                            running.abort_all();
                            let client = client.lock().await;
                            if let Err(ie) = abort_upload(&client, &pc).await {
                                return Err(ie)
                                    .context(format!("Failed to upload part #{}", part_number))
                                    .context(e);
                            } else {
                                return Err(e.into());
                            }
                        }
                        Err(e) => todo!("Join error {}", e),
                    }
                }
            }
            Err(e) => {
                println!("ERROR, aborting");
                running.abort_all();
                let client = client.lock().await;
                if let Err(ie) = abort_upload(&client, &pc).await {
                    return Err(ie)
                        .context(format!("Failed to read part #{}", part_number))
                        .context(e);
                } else {
                    return Err(e.into());
                }
            }
        }
    }

    // All done
    if total == 0 {
        println!("Read 0 bytes");
        return Err(anyhow!("Read 0 bytes"));
    }

    while let Some(jh) = running.join_next().await {
        match jh {
            Ok(Ok(part)) => upload_parts.push(part),
            Ok(Err(e)) => {
                println!("ERROR, aborting");
                running.abort_all();
                let client = client.lock().await;
                if let Err(ie) = abort_upload(&client, &pc).await {
                    return Err(ie)
                        .context(format!("Failed to upload part #{}", part_number))
                        .context(e);
                } else {
                    return Err(e.into());
                }
            }
            Err(e) => todo!("Join error {}", e),
        }
    }

    let completed_multipart_upload = CompletedMultipartUpload::builder()
        .set_parts(Some(upload_parts))
        .build();

    let client = client.lock().await;

    let cmu = client
        .complete_multipart_upload()
        .bucket(&pc.bucket)
        .key(&pc.key)
        .multipart_upload(completed_multipart_upload)
        .upload_id(&pc.id)
        .send()
        .await;
    if let Err(e) = cmu {
        if let Err(ie) = abort_upload(&client, &pc).await {
            return Err(ie)
                .context(format!("Failed to finalize upload"))
                .context(e);
        } else {
            return Err(e.into());
        }
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
    client: Arc<Mutex<Client>>,
    pc: UploadConfig,
    data: Vec<u8>,
    part_number: i32,
) -> Result<CompletedPart, SdkError<UploadPartError>> {
    let c = client.lock().await;
    upload_part(&c, &pc, data, part_number).await
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

#[::tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = [0x42; 32];
    let nonce = [0x24; 12];
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let client = aws_sdk_s3::Client::new(&config);
    let cipher = chacha20::ChaCha20::new(&key.into(), &nonce.into());

    // ... make some calls with the client
    let resp = client
        .list_buckets()
        .bucket_region("eu-north-1")
        .send()
        .await;

    match resp {
        Ok(ls) => {
            for b in ls.buckets() {
                println!("{}", b.name().unwrap_or("unknown"));
            }
        }
        Err(e) => {
            println!("Failed to get: {}", e.into_service_error());
        }
    }

    let resp = client
        .list_multipart_uploads()
        .bucket("testbucket-paws")
        .send()
        .await;

    println!("In progress uploads:");
    match resp {
        Ok(ls) => {
            for b in ls.uploads() {
                println!("{} ({:?})", b.key().unwrap_or("unknown"), b.storage_class());

                let pc = UploadConfig {
                    key: b.key().expect("Missing key").to_string(),
                    bucket: "testbucket-paws".to_string(),
                    id: b.upload_id().expect("No upload id").to_string(),
                };

                abort_upload(&client, &pc).await?;
            }
        }
        Err(e) => {
            println!("Failed to get: {}", e.into_service_error());
        }
    };

    let snaps = zfs::get_current_state(&client, "testbucket-paws").await?;
    println!("Current snapshots:");
    for s in snaps {
        println!("{}", s);
    }
    println!("That's all");

    let c = open_full("zpool", "T3").unwrap();

    //tokio::time::sleep(time::Duration::from_millis(200)).await;

    let o = c.stdout.expect("No child output stream");

    let o = tokio::io::BufReader::new(o);

    let mut pc = UploadConfig {
        key: "AWSAVE-full@zpool@T3".to_string(),
        bucket: "testbucket-paws".to_string(),
        id: "asd001".to_string(),
    };

    // Open upload
    let multipart_upload_res: CreateMultipartUploadOutput = client
        .create_multipart_upload()
        .bucket(&pc.bucket)
        .key(&pc.key)
        .send()
        .await?;

    let upload_id = multipart_upload_res
        .upload_id()
        .ok_or(anyhow!("Missing upload_id after CreateMultipartUpload"))?;
    pc.id = upload_id.to_string();

    let cc = Arc::new(Mutex::new(client));

    match encypt_and_upload(cc.clone(), pc, o, cipher).await {
        Ok(hash) => println!("Upload done, hash is {}", hex::encode(hash)),
        Err(e) => {
            println!("Cought error {}", e);

            print_lines(c.stderr.expect("No child stderr")).await?;
        }
    }

    Ok(())
}
