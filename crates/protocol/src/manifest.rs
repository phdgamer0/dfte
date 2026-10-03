use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Manifest {
    transfer_id: Uuid,
    files: Vec<FileEntry>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    relative_path: String,
    size: u64,
    modified_time: i64,
    permissions: Option<u32>,
    conent_hash: [u8; 32],
    chunk_count: u32,
}

const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_PAYLOAD: u32 = 4 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 1024 * size_of::<char>();
const MAX_MANIFEST_ENTERY: usize = 20000;
