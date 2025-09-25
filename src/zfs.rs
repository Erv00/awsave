use std::{collections::{HashMap, HashSet}, fmt::{self, Write}};

use aws_sdk_s3::{Client, types::ObjectStorageClass};
use aws_smithy_types_convert::date_time::DateTimeExt;
use chrono::TimeDelta;

const SNAPSHOT_PREFIX: &str = "AWSAVE-";

type UtcDatetime = chrono::DateTime<chrono::Utc>;

#[derive(Clone)]
pub struct FullSnapshot {
    dataset: String,
    name: String,
    date: UtcDatetime,
    size: usize,
    storage_class: Option<ObjectStorageClass>,
}

impl FullSnapshot {
    fn new(
        dataset: String,
        name: String,
        date: UtcDatetime,
        size: usize,
        storage_class: Option<ObjectStorageClass>,
    ) -> Self {
        Self {
            dataset,
            name,
            date,
            size,
            storage_class,
        }
    }
}

#[derive(Clone)]
pub struct IncrementalSnapshot {
    dataset: String,
    name: String,
    date: UtcDatetime,
    size: usize,
    storage_class: Option<ObjectStorageClass>,

    base: String,
}

impl IncrementalSnapshot {
    fn new(
        dataset: String,
        name: String,
        date: UtcDatetime,
        size: usize,
        storage_class: Option<ObjectStorageClass>,
        base: String,
    ) -> Self {
        Self {
            dataset,
            name,
            date,
            size,
            storage_class,
            base,
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
        f.write_str(if let Snapshot::Full(_) = self {"Full snapshot "} else {"Incremental snapshot "})?;
        f.write_str(self.dataset())?;
        f.write_char('@')?;
        f.write_str(self.name())?;
        f.write_fmt(format_args!(" taken at {}, class is {}", self.date(), self.storage_class().as_ref().map(|s|s.to_string()).unwrap_or("MISSING".to_string())))
    }
}

impl Snapshot {
    fn name(&self) -> &str {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.name,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.name,
        }
    }

    fn dataset(&self) -> &str {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.dataset,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.dataset,
        }
    }

    fn date(&self) -> &UtcDatetime {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.date,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.date,
        }
    }

    fn storage_class(&self) -> &Option<ObjectStorageClass> {
        match self {
            Snapshot::Full(full_snapshot) => &full_snapshot.storage_class,
            Snapshot::Incremental(incremental_snapshot) => &incremental_snapshot.storage_class,
        }
    }
}

enum Action {
    Delete(Snapshot),
    CreateFull { dataset: String },
    CreateIncremental { dataset: String, from: String },
}

fn check_state(desired_datasets: &[&str], state: &[Snapshot], now: UtcDatetime) -> Vec<Action> {
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
        if let Some(t) = latest.get(s.dataset()) {
            if t.date() > s.date() {
                continue;
            }
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
        println!("Too many objects returned");
    }

    Ok(objs
        .contents
        .unwrap_or_default()
        .into_iter()
        .filter_map(|o| {
            let name = o.key?;
            let date = o.last_modified?;
            let size = o.size?.try_into().ok()?;
            let storage_class = o.storage_class;

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
                ))),
                "incremental" => {
                    let base = parts.get(3)?;
                    Some(Snapshot::Incremental(IncrementalSnapshot::new(
                        dataset.to_string(),
                        name.to_string(),
                        date.to_chrono_utc().ok()?,
                        size,
                        storage_class,
                        base.to_string(),
                    )))
                }
                _ => None,
            }
        })
        .collect())
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
            size: 200,
            date: now - TimeDelta::days(1),
            storage_class: None,
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
            size: 200,
            date: now - TimeDelta::days(10),
            storage_class: None,
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
            size: 200,
            date: now - TimeDelta::days(1000),
            storage_class: None,
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
