mod error;
mod header;
mod manifest;

pub type Result<T> = core::result::Result<T, error::ProtocolError>;

pub const fn chunk_count(file_size: u64, chunk_size: u64) -> u64 {
    debug_assert!(chunk_size != 0);
    file_size.div_ceil(chunk_size)
}

pub fn chunk_offset(index: u64, chunk_size: u64) -> Result<u64> {
    debug_assert!(chunk_size != 0);
    index.checked_mul(chunk_size).ok_or(error::ProtocolError::ArithmeticOverflow)
}

pub fn chunk_len(file_size: u64, index: u64, chunk_size: u64) -> Result<u64> {
    debug_assert!(chunk_size != 0);
    let offset = chunk_offset(index, chunk_size)?;
    if offset >= file_size {
        return Ok(0);
    }
    Ok((file_size - offset).min(chunk_size))
}
