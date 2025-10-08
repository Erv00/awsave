use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub upload_chunk_size: usize,
    pub max_concurrent: usize,
    pub bucket: String,
    pub master_key: String,
    pub desired_datasets: Vec<String>,
}
