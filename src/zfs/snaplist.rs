use crate::zfs::UtcDatetime;
use chrono::{DateTime, ParseError, Utc};
use serde::{Deserialize, Deserializer};
use std::fmt::{Display, Formatter};
use serde_json::Value;
use tokio::process::Command;

#[derive(Deserialize)]
struct ZfsSnapshotListEntryInner {
    name: String,
    dataset: String,
    snapshot_name: String,
}

pub struct ZfsSnapshotListEntry {
    pub name: String,
    pub dataset: String,
    pub snapshot_name: String,
    pub creation_date: UtcDatetime,
}

impl Display for ZfsSnapshotListEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl TryFrom<ZfsSnapshotListEntryInner> for ZfsSnapshotListEntry {
    type Error = ParseError;

    fn try_from(value: ZfsSnapshotListEntryInner) -> Result<Self, Self::Error> {
        let d = chrono::NaiveDate::parse_from_str(value.snapshot_name.as_str(), "%Y%m%d")?;
        let d = d
            .and_hms_opt(0, 0, 0)
            .expect("Could not add 00:00:00 to date")
            .and_utc();

        Ok(Self {
            name: value.name,
            dataset: value.dataset,
            snapshot_name: value.snapshot_name,
            creation_date: d,
        })
    }
}

impl<'de> Deserialize<'de> for ZfsSnapshotListEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = ZfsSnapshotListEntryInner::deserialize(deserializer)?;

        Self::try_from(inner).map_err(serde::de::Error::custom)
    }
}

pub type ZfsSnapshotList = Vec<ZfsSnapshotListEntry>;

pub async fn get_all_local_snapshots() -> anyhow::Result<ZfsSnapshotList> {
    let c = Command::new("sh")
        .arg("-c")
        .arg("zfs list -t snapshot -j | jq '[.datasets[]]'")
        .output()
        .await?;

    let vals: Vec<Value> = serde_json::from_slice(&c.stdout)?;
    let mut res: Vec<ZfsSnapshotListEntry> = Vec::new();
    for v in vals {
        match serde_json::from_value::<ZfsSnapshotListEntry>(v) {
            Ok(v) => res.push(v),
            Err(_) => {}
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::{Error, Value};

    #[test]
    fn test_snaplist_entry() {
        let raw = r#"
{
      "name": "ZFS_Pool/Archived_Projects@20251008",
      "type": "SNAPSHOT",
      "pool": "ZFS_Pool",
      "createtxg": "11113007",
      "dataset": "ZFS_Pool/Archived_Projects",
      "snapshot_name": "20251008",
      "properties": {
        "used": {
          "value": "0B",
          "source": {
            "type": "NONE",
            "data": "-"
          }
        },
        "available": {
          "value": "-",
          "source": {
            "type": "NONE",
            "data": "-"
          }
        },
        "referenced": {
          "value": "80.0M",
          "source": {
            "type": "NONE",
            "data": "-"
          }
        },
        "mountpoint": {
          "value": "-",
          "source": {
            "type": "NONE",
            "data": "-"
          }
        }
      }
    }
"#;

        let parsed: ZfsSnapshotListEntry = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.name, "ZFS_Pool/Archived_Projects@20251008");
        assert_eq!(parsed.dataset, "ZFS_Pool/Archived_Projects");
        assert_eq!(parsed.snapshot_name, "20251008");
        assert_eq!(
            parsed.creation_date,
            Utc.with_ymd_and_hms(2025, 10, 8, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_snaplist_multientry() {
        let raw = r#"[
        {
    "name": "ZFS_Pool/bastille/templates@20250808",
    "type": "SNAPSHOT",
    "pool": "ZFS_Pool",
    "createtxg": "10090055",
    "dataset": "ZFS_Pool/bastille/templates",
    "snapshot_name": "20250808",
    "properties": {
      "used": {
        "value": "0B",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "available": {
        "value": "-",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "referenced": {
        "value": "140K",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "mountpoint": {
        "value": "-",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      }
    }
  },
  {
    "name": "ZFS_Pool/xilinx@20250808",
    "type": "SNAPSHOT",
    "pool": "ZFS_Pool",
    "createtxg": "10090055",
    "dataset": "ZFS_Pool/xilinx",
    "snapshot_name": "20250808",
    "properties": {
      "used": {
        "value": "0B",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "available": {
        "value": "-",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "referenced": {
        "value": "146G",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      },
      "mountpoint": {
        "value": "-",
        "source": {
          "type": "NONE",
          "data": "-"
        }
      }
    }
  }
]"#;
        let vals: Vec<Value> = serde_json::from_str(raw).unwrap();
        let mut vs: Vec<ZfsSnapshotListEntry> = Vec::new();
        for v in vals {
            match serde_json::from_value::<ZfsSnapshotListEntry>(v) {
                Ok(v) => vs.push(v),
                Err(_) => {}
            }
        }
        //let parsed: Vec<Result<ZfsSnapshotListEntry, serde_json::Error>> = serde_json::from_str(raw).unwrap();
        let parsed = vs;
        assert_eq!(parsed.len(), 2);
    }
}
