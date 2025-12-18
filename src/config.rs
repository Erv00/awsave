use std::path::PathBuf;
use either::Either;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub upload_chunk_size: usize,
    pub max_concurrent: usize,
    pub bucket: String,
    pub master_key: String,
    pub desired_datasets: Vec<String>,
    pub glacier_size_limit: usize,
}

#[derive(Deserialize)]
pub struct FolderUpload {
    name: String,
    source_path: Option<PathBuf>,
    find_command: Option<String>
}