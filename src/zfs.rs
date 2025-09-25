use std::collections::{HashMap, HashSet};

use chrono::TimeDelta;

type UtcDatetime =  chrono::DateTime<chrono::Utc>;

#[derive(Clone)]
struct FullSnapshot {
    dataset: String,
    name: String,
    date: UtcDatetime,
    size: usize
}

#[derive(Clone)]
struct IncrementalSnapshot {
    dataset: String,
    name: String,
    date: UtcDatetime,
    size: usize,

    base: String,
    base_date: UtcDatetime,
}

#[derive(Clone)]
enum Snapshot {
    Full(FullSnapshot),
    Incremental(IncrementalSnapshot)
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
}

enum Action {
    Delete(Snapshot),
    CreateFull{dataset: String},
    CreateIncremental{dataset: String, from: String}
}

fn check_state(desired_datasets: &[&str], state: &[Snapshot], now: UtcDatetime) -> Vec<Action> {
    let mut needed_actions: Vec<Action> = Vec::new();
    let mut new_snaps: HashSet<&str> = HashSet::new();
    // All desired datasets MUST have a full copy that is less then 180 days old
    let current_fulls: Vec<&str> = state.iter().filter_map(|s| {
            match s {
                Snapshot::Full(full_snapshot) => {
                    if now-full_snapshot.date <= TimeDelta::days(180) {
                        Some(full_snapshot.dataset.as_ref())
                    } else {
                        None
                    }
                },
                Snapshot::Incremental(_) => None,
            }
        }).collect();
    for ds in desired_datasets {
        if !current_fulls.contains(ds) {
            needed_actions.push(Action::CreateFull { dataset: ds.to_string()});
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
            Some(t) if now-t.date() > TimeDelta::weeks(1) => {
                // The latest is too old
                needed_actions.push(Action::CreateIncremental { dataset: ds.to_string(), from: t.name().to_owned()});
                new_snaps.insert(ds);
            },
            Some(_) => {}, // Latest is good enough
            None => panic!("No snapshot was found for {ds}, but no full was ordered to be created?"), // No snapshot was found, but no full was ordered to be created?
        }
    }

    // Snapshots older than 190 days should be deleted
    for s in state {
        if now-s.date() > TimeDelta::days(190) {
            needed_actions.push(Action::Delete(s.clone()));
        }
    }

    needed_actions
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
            date: now-TimeDelta::days(1)
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
            date: now-TimeDelta::days(10)
        };
        let state = vec![Snapshot::Full(fs)];

        let actions = check_state(&ds, &state, now);

        assert_eq!(actions.len(), 1);
        assert!(match &actions[0] {
            Action::CreateIncremental { dataset , from} => dataset == "test1" && from == "T1",
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
            date: now-TimeDelta::days(1000)
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
                snap.dataset == "test1" &&
                snap.name == "T1"
            },
            _ => false,
        });
    }
}