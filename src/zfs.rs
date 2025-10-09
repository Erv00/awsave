use std::{
    collections::{HashMap, HashSet}, fmt::{self, Write}, io::BufRead, process::ExitStatus
};

use aws_sdk_s3::{
    Client,
    operation::delete_object::DeleteObjectOutput,
    types::{ObjectStorageClass, RestoreStatus},
};
use aws_smithy_types_convert::date_time::DateTimeExt;
use chacha20::cipher::KeyIvInit;
use chrono::TimeDelta;

use anyhow::anyhow;
use log::error;
use tokio::process::Command;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::UploadConfig;

const SNAPSHOT_PREFIX: &str = "AWSAVE-";

type UtcDatetime = chrono::DateTime<chrono::Utc>;

#[derive(Clone)]
pub struct FullSnapshot {
    pub dataset: String,
    name: String,
    date: UtcDatetime,
    size: Option<usize>,
    storage_class: Option<ObjectStorageClass>,
    restore_status: Option<RestoreStatus>,
}

impl FullSnapshot {
    fn new(
        dataset: String,
        name: String,
        date: UtcDatetime,
        size: Option<usize>,
        storage_class: Option<ObjectStorageClass>,
        restore_status: Option<RestoreStatus>,
    ) -> Self {
        Self {
            dataset,
            name,
            date,
            size,
            storage_class,
            restore_status,
        }
    }
}

#[derive(Clone)]
pub struct IncrementalSnapshot {
    pub dataset: String,
    pub name: String,
    pub date: UtcDatetime,
    pub size: Option<usize>,
    pub storage_class: Option<ObjectStorageClass>,
    pub restore_status: Option<RestoreStatus>,

    base: String,
}

impl IncrementalSnapshot {
    fn new(
        dataset: String,
        name: String,
        date: UtcDatetime,
        size: Option<usize>,
        storage_class: Option<ObjectStorageClass>,
        restore_status: Option<RestoreStatus>,
        base: String,
    ) -> Self {
        Self {
            dataset,
            name,
            date,
            size,
            storage_class,
            restore_status,
            base,
        }
    }
}

pub enum AvailabilityInfo {
    CanRestore,
    RestoreInProgress,
    Available,
}

impl From<(ObjectStorageClass, Option<RestoreStatus>)> for AvailabilityInfo {
    fn from(value: (ObjectStorageClass, Option<RestoreStatus>)) -> Self {
        let (ty, rs) = value;
        match ty {
            ObjectStorageClass::DeepArchive | ObjectStorageClass::Glacier => match rs {
                None => unimplemented!("Restore status is None"),
                Some(rs) => match (rs.is_restore_in_progress, rs.restore_expiry_date) {
                    (Some(true), _) => Self::RestoreInProgress,
                    (Some(false), Some(_)) => Self::Available,
                    (None, _) => Self::CanRestore,
                    _ => unimplemented!("Snapshot has unknown availability: {}, {:?}", ty, rs),
                },
            },
            ObjectStorageClass::Standard => AvailabilityInfo::Available,
            _ => unimplemented!("Snapshot has unknown availability: {}, {:?}", ty, rs),
        }
    }
}

#[derive(Clone)]
pub enum Snapshot {
    Full(FullSnapshot),
    Incremental(IncrementalSnapshot),
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if let Snapshot::Full(_) = self {
            "Full snapshot "
        } else {
            "Incremental snapshot "
        })?;
        f.write_str(self.dataset())?;
        f.write_char('@')?;
        f.write_str(self.name())?;
        f.write_fmt(format_args!(
            " taken at {}, class is {}",
            self.date(),
            self.storage_class()
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or("MISSING".to_string())
        ))
    }
}

impl Snapshot {
    pub fn name(&self) -> &str {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.name,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.name,
        }
    }

    pub fn dataset(&self) -> &str {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.dataset,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.dataset,
        }
    }

    pub fn date(&self) -> &UtcDatetime {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.date,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.date,
        }
    }

    pub fn storage_class(&self) -> &Option<ObjectStorageClass> {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.storage_class,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.storage_class,
        }
    }

    pub fn aws_key(&self) -> String {
        match self {
            Snapshot::Full(s) => format!("{}full@{}@{}", SNAPSHOT_PREFIX, s.dataset, s.name),
            Snapshot::Incremental(s) => format!(
                "{}incremental@{}@{}@{}",
                SNAPSHOT_PREFIX, s.dataset, s.name, s.base
            ),
        }
    }

    pub fn availability(&self) -> Option<AvailabilityInfo> {
        let ty = self.storage_class().to_owned()?;
        let stat = match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.restore_status,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.restore_status,
        }
        .to_owned();

        Some(AvailabilityInfo::from((ty, stat)))
    }

    pub fn size(&self) -> &Option<usize> {
         match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.size,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.size,
        }
    }

    pub async fn take_full(dataset: &str, name: &str) -> anyhow::Result<Self> {
        let s = Command::new("sudo")
            .arg("zfs")
            .arg("list")
            .arg("-t")
            .arg("snapshot")
            .arg(format!("{}@{}", dataset, name))
            .spawn()?
            .wait()
            .await?;

        if !s.success() {
            // Did not exist
            Command::new("sudo")
                .arg("zfs")
                .arg("snapshot")
                .arg("-r")
                .arg(format!("{}@{}", dataset, name))
                .spawn()?
                .wait()
                .await?;
        }

        let s = Command::new("sudo")
            .arg("zfs")
            .arg("send")
            .arg("-PnR")
            .arg(format!("{}@{}", dataset, name))
            .output()
            .await?;

        if !s.status.success() || s.stdout.len() == 0 {
            return Err(anyhow!(
                "Failed to take full snapshot {}@{}: {:?}",
                dataset,
                name,
                s.status.code()
            ));
        }

        let s = s.stdout.lines();
        if let Some(Ok(ll)) = s.last() {
            if let Some(size) = ll.split('\t').last() {
                let size = usize::from_str_radix(size, 10)?;
                
                Ok(Self::Full(FullSnapshot {
                    dataset: dataset.to_owned(),
                    name: name.to_owned(),
                    date: chrono::Utc::now(),
                    size: Some(size),
                    storage_class: None,
                    restore_status: None,
                }))
            } else {
                Err(anyhow!("Failed to split"))
            }
        } else {
            Err(anyhow!("Empty stdout"))
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UploadResult {
    pub filename: String,
    pub hash: Vec<u8>,
    pub key: [u8; 32],
    pub iv: [u8; 12],
}

pub enum Action {
    Delete(Snapshot),
    CreateFull { dataset: String },
    CreateIncremental { dataset: String, from: String },
}

pub enum ActionPerformResult {
    Delete(DeleteObjectOutput),
    CreateFull(UploadResult),
    CreateIncremental(UploadResult),
}

impl Action {
    pub async fn perform_aws(&self, client: &Client) -> anyhow::Result<ActionPerformResult> {
        match self {
            Action::Delete(snapshot) => Ok(ActionPerformResult::Delete(
                Self::perform_aws_delete(snapshot, client).await?,
            )),
            Action::CreateFull { dataset } => Ok(ActionPerformResult::CreateFull(
                Self::perform_aws_create_full(dataset, client).await?,
            )),
            Action::CreateIncremental { dataset, from } => {
                Ok(ActionPerformResult::CreateIncremental(
                    Self::perform_aws_create_incremental(dataset, from, client).await?,
                ))
            }
        }
    }

    fn perform_aws_delete(
        s: &Snapshot,
        client: &Client,
    ) -> impl Future<
        Output = Result<
            DeleteObjectOutput,
            aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::delete_object::DeleteObjectError>,
        >,
    > {
        client
            .delete_object()
            .bucket(&crate::CONFIG.bucket)
            .key(s.aws_key())
            .send()
    }

    async fn perform_aws_create_full(ds: &String, client: &Client) -> anyhow::Result<UploadResult> {
        let now = chrono::Utc::now();
        let snapname = now.format("%Y%m%d").to_string();

        // Make snapshot
        let snap = Snapshot::take_full(ds, &snapname).await?;

        let mut pc = UploadConfig {
            key: snap.aws_key(),
            bucket: crate::CONFIG.bucket.clone(),
            id: "asd001".to_string(),
        };

        let c = crate::open_full(ds, &snapname)?;

        let o = c.stdout.expect("No child output stream");

        let o = tokio::io::BufReader::new(o);

        let multipart_upload_res = client
            .create_multipart_upload()
            .bucket(&pc.bucket)
            .key(&pc.key)
            .send()
            .await?;

        let upload_id = multipart_upload_res
            .upload_id()
            .ok_or(anyhow!("Missing upload_id after CreateMultipartUpload"))?;
        pc.id = upload_id.to_string();

        let (key, iv) = crate::kex::generate_key();
        let cipher = chacha20::ChaCha20::new(&key.into(), &iv.into());
        let filename = pc.key.clone();

        let hash = crate::encypt_and_upload(client.clone(), pc, o, cipher, snap.size().unwrap()).await?;

        Ok(UploadResult {
            filename,
            hash,
            key,
            iv,
        })
    }

    async fn perform_aws_create_incremental(
        ds: &String,
        from: &String,
        client: &Client,
    ) -> anyhow::Result<UploadResult> {
        let now = chrono::Utc::now();
        let snapname = now.format("%Y%m%d").to_string();

        // Make snapshot
        //if !take_snapshot(ds, &snapname).await?.success() {
        //    return Err(anyhow!("Failed to make snapshot"));
        //}

        let snap = IncrementalSnapshot::new(
            ds.to_owned(),
            snapname.clone(),
            now,
            None,
            None,
            None,
            from.to_owned(),
        );

        let mut pc = UploadConfig {
            key: Snapshot::Incremental(snap).aws_key(),
            bucket: crate::CONFIG.bucket.clone(),
            id: "asd001".to_string(),
        };

        let c = crate::open_incremental(ds, from, &snapname)?;

        let o = c.stdout.expect("No child output stream");

        let o = tokio::io::BufReader::new(o);

        let multipart_upload_res = client
            .create_multipart_upload()
            .bucket(&pc.bucket)
            .key(&pc.key)
            .send()
            .await?;

        let upload_id = multipart_upload_res
            .upload_id()
            .ok_or(anyhow!("Missing upload_id after CreateMultipartUpload"))?;
        pc.id = upload_id.to_string();

        let (key, iv) = crate::kex::generate_key();
        let cipher = chacha20::ChaCha20::new(&key.into(), &iv.into());
        let filename = pc.key.clone();

        todo!();
        //let hash = crate::encypt_and_upload(client.clone(), pc, o, cipher, snap.size.clo.unwrap()).await?;

        /*Ok(UploadResult {
            filename,
            hash,
            key,
            iv,
        })*/
    }
}

pub fn check_state(desired_datasets: &[&str], state: &[Snapshot], now: UtcDatetime) -> Vec<Action> {
    let mut needed_actions: Vec<Action> = Vec::new();
    let mut new_snaps: HashSet<&str> = HashSet::new();
    // All desired datasets MUST have a full copy that is less then 180 days old
    let current_fulls: Vec<&str> = state
        .iter()
        .filter_map(|s| match s {
            Snapshot::Full(full_snapshot) => {
                if now - full_snapshot.date <= TimeDelta::days(180) {
                    Some(full_snapshot.dataset.as_ref())
                } else {
                    None
                }
            }
            Snapshot::Incremental(_) => None,
        })
        .collect();
    for ds in desired_datasets {
        if !current_fulls.contains(ds) {
            needed_actions.push(Action::CreateFull {
                dataset: ds.to_string(),
            });
            new_snaps.insert(ds);
        }
    }

    // If desired datasets MUST have a (possibly incremental) copy that is less than a week old
    let mut latest: HashMap<&str, &Snapshot> = HashMap::new();
    for s in state {
        if let Some(t) = latest.get(s.dataset())
            && t.date() > s.date()
        {
            continue;
        }
        latest.insert(s.dataset(), s);
    }

    for ds in desired_datasets {
        if new_snaps.contains(ds) {
            // A new snap will be created, ignore
            continue;
        }

        match latest.get(ds) {
            Some(t) if now - t.date() > TimeDelta::weeks(1) => {
                // The latest is too old
                needed_actions.push(Action::CreateIncremental {
                    dataset: ds.to_string(),
                    from: t.name().to_owned(),
                });
                new_snaps.insert(ds);
            }
            Some(_) => {} // Latest is good enough
            None => {
                panic!("No snapshot was found for {ds}, but no full was ordered to be created?")
            } // No snapshot was found, but no full was ordered to be created?
        }
    }

    // Snapshots older than 190 days should be deleted
    for s in state {
        if now - s.date() > TimeDelta::days(190) {
            needed_actions.push(Action::Delete(s.clone()));
        }
    }

    needed_actions
}

pub async fn get_current_state(client: &Client, bucket: &str) -> anyhow::Result<Vec<Snapshot>> {
    let objs = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(SNAPSHOT_PREFIX)
        .send()
        .await?;

    if let Some(true) = objs.is_truncated() {
        error!("Too many objects returned");
    }

    Ok(objs
        .contents
        .unwrap_or_default()
        .into_iter()
        .filter_map(|o| {
            let name = o.key?;
            if name.ends_with(".key") {
                return None;
            }
            let date = o.last_modified?;
            let size = o.size.map(|s| s.try_into().expect("negative size"));
            let storage_class = o.storage_class;
            let restore_status = o.restore_status;

            let name = name
                .strip_prefix(SNAPSHOT_PREFIX)
                .expect("AWS lied to me, key does not start with prefix");
            let parts: Vec<&str> = name.split('@').collect();

            let snap_type = parts.get(0)?;
            let dataset = parts.get(1)?;
            let name = parts.get(2)?;

            match *snap_type {
                "full" => Some(Snapshot::Full(FullSnapshot::new(
                    dataset.to_string(),
                    name.to_string(),
                    date.to_chrono_utc().ok()?,
                    size,
                    storage_class,
                    restore_status,
                ))),
                "incremental" => {
                    let base = parts.get(3)?;
                    Some(Snapshot::Incremental(IncrementalSnapshot::new(
                        dataset.to_string(),
                        name.to_string(),
                        date.to_chrono_utc().ok()?,
                        size,
                        storage_class,
                        restore_status,
                        base.to_string(),
                    )))
                }
                _ => None,
            }
        })
        .collect())
}


async fn delete_snapshot(dataset: &str, name: &str) -> Result<ExitStatus, std::io::Error> {
    Command::new("zfs")
        .arg("destroy")
        .arg(format!("{}@{}", dataset, name))
        .spawn()?
        .wait()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_missing_created() {
        let ds = vec!["test1"];
        let state = Vec::<Snapshot>::new();
        let now = chrono::Utc::now();

        let actions = check_state(&ds, &state, now);

        assert_eq!(actions.len(), 1);
        assert!(match &actions[0] {
            Action::CreateFull { dataset } => dataset == "test1",
            _ => false,
        });
    }

    #[test]
    fn test_basic_okay() {
        let now = chrono::Utc::now();
        let ds = vec!["test1"];
        let fs = FullSnapshot {
            dataset: "test1".to_owned(),
            name: "T1".to_owned(),
            size: Some(200),
            date: now - TimeDelta::days(1),
            storage_class: None,
            restore_status: None,
        };
        let state = vec![Snapshot::Full(fs)];

        let actions = check_state(&ds, &state, now);

        assert_eq!(actions.len(), 0);
    }

    #[test]
    fn test_basic_missing_incremental() {
        let now = chrono::Utc::now();
        let ds = vec!["test1"];
        let fs = FullSnapshot {
            dataset: "test1".to_owned(),
            name: "T1".to_owned(),
            size: Some(200),
            date: now - TimeDelta::days(10),
            storage_class: None,
            restore_status: None,
        };
        let state = vec![Snapshot::Full(fs)];

        let actions = check_state(&ds, &state, now);

        assert_eq!(actions.len(), 1);
        assert!(match &actions[0] {
            Action::CreateIncremental { dataset, from } => dataset == "test1" && from == "T1",
            _ => false,
        });
    }

    #[test]
    fn test_basic_old_full() {
        let now = chrono::Utc::now();
        let ds = vec!["test1"];
        let fs = FullSnapshot {
            dataset: "test1".to_owned(),
            name: "T1".to_owned(),
            size: Some(200),
            date: now - TimeDelta::days(1000),
            storage_class: None,
            restore_status: None,
        };
        let state = vec![Snapshot::Full(fs)];

        let actions = check_state(&ds, &state, now);

        assert_eq!(actions.len(), 2);
        assert!(match &actions[0] {
            Action::CreateFull { dataset } => dataset == "test1",
            _ => false,
        });
        assert!(match &actions[1] {
            Action::Delete(Snapshot::Full(snap)) => {
                snap.dataset == "test1" && snap.name == "T1"
            }
            _ => false,
        });
    }
}
