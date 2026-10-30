// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

//! Bounded pool of pre-allocated chunk buffers (manual §14/§27/§28).
//!
//! Buffers are allocated once when the pool is built and cycled; the pool's
//! bound *is* the backpressure mechanism: [`BufferPool::acquire`] waits until a
//! [`PoolBuffer`] is dropped.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;
use tokio::sync::Semaphore;

use crate::error::{Result, StorageError};

/// Target alignment for buffer starts (one page). Best-effort: achieved by
/// over-allocating and offsetting into the allocation, no `unsafe` required.
pub const BUFFER_ALIGN: usize = 4096;

/// One owned backing allocation plus the offset of its aligned start.
struct RawBuf {
    storage: Box<[u8]>,
    start: usize,
}

impl RawBuf {
    fn new(capacity: usize) -> Self {
        let storage = vec![0u8; capacity + BUFFER_ALIGN].into_boxed_slice();
        let start = storage.as_ptr().align_offset(BUFFER_ALIGN).min(BUFFER_ALIGN);
        Self { storage, start }
    }

    fn slice(&self, capacity: usize) -> &[u8] {
        &self.storage[self.start..self.start + capacity]
    }

    fn slice_mut(&mut self, capacity: usize) -> &mut [u8] {
        &mut self.storage[self.start..self.start + capacity]
    }
}

struct Inner {
    free: ArrayQueue<RawBuf>,
    permits: Semaphore,
    capacity: usize,
    count: usize,
}

/// Fixed-size, bounded buffer pool. Cheap to clone (shared `Arc`).
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<Inner>,
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool").field("buffer_capacity", &self.inner.capacity).field("count", &self.inner.count).field("available", &self.available()).finish()
    }
}

impl BufferPool {
    /// Allocate `count` buffers of `capacity` bytes each, up front.
    /// A `count` of zero is bumped to one so `acquire` can never deadlock forever.
    pub fn new(count: usize, capacity: usize) -> Self {
        let count = count.max(1);
        let free = ArrayQueue::new(count);
        for _ in 0..count {
            // Cannot fail: queue capacity == count.
            let _ = free.push(RawBuf::new(capacity));
        }
        Self { inner: Arc::new(Inner { free, permits: Semaphore::new(count), capacity, count }) }
    }

    /// Pool of `count` buffers sized to [`crate::CHUNK_SIZE`].
    pub fn for_chunks(count: usize) -> Self {
        // CHUNK_SIZE (4 MiB) fits in usize on every supported target.
        Self::new(count, crate::chunk::CHUNK_SIZE as usize)
    }

    /// Wait for a free buffer. This await is the send/receive pipeline's backpressure.
    ///
    /// Cancel-safe: dropping the future before it resolves takes no buffer.
    pub async fn acquire(&self) -> PoolBuffer {
        match self.inner.permits.acquire().await {
            Ok(permit) => permit.forget(),
            // The semaphore is private and never closed, so this cannot happen.
            Err(_) => unreachable!("buffer pool semaphore closed"),
        }
        self.take()
    }

    /// Take a free buffer without waiting, or `None` if the pool is exhausted.
    pub fn try_acquire(&self) -> Option<PoolBuffer> {
        self.inner.permits.try_acquire().ok()?.forget();
        Some(self.take())
    }

    /// Called only while holding a (forgotten) permit, so a buffer is guaranteed free.
    fn take(&self) -> PoolBuffer {
        let raw = self
            .inner
            .free
            .pop()
            // Defensive: permits == queued buffers is an invariant; if it were ever
            // violated, allocating keeps the caller correct rather than panicking.
            .unwrap_or_else(|| RawBuf::new(self.inner.capacity));
        PoolBuffer { raw: Some(raw), len: self.inner.capacity, pool: Arc::clone(&self.inner) }
    }

    /// Number of buffers currently free.
    pub fn available(&self) -> usize {
        self.inner.permits.available_permits()
    }

    /// Total number of buffers in the pool.
    pub fn count(&self) -> usize {
        self.inner.count
    }

    /// Capacity of each buffer in bytes.
    pub fn buffer_capacity(&self) -> usize {
        self.inner.capacity
    }
}

/// RAII handle to a pooled buffer; returned to the pool on drop.
///
/// Derefs to `[u8]` of length [`PoolBuffer::len`] (initially the full capacity).
/// Contents are not cleared between uses.
pub struct PoolBuffer {
    raw: Option<RawBuf>,
    len: usize,
    pool: Arc<Inner>,
}

impl PoolBuffer {
    /// Usable capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.pool.capacity
    }

    /// Set the logical length; must be `<= capacity()`.
    pub fn set_len(&mut self, len: usize) -> Result<()> {
        if len > self.capacity() {
            return Err(StorageError::BufferTooSmall { needed: len as u64, capacity: self.capacity() as u64 });
        }
        self.len = len;
        Ok(())
    }

    /// The whole capacity, regardless of the logical length (e.g. to read into).
    pub fn full_mut(&mut self) -> &mut [u8] {
        let cap = self.pool.capacity;
        match self.raw.as_mut() {
            Some(raw) => raw.slice_mut(cap),
            None => &mut [],
        }
    }
}

impl Deref for PoolBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self.raw.as_ref() {
            Some(raw) => &raw.slice(self.pool.capacity)[..self.len],
            None => &[],
        }
    }
}

impl DerefMut for PoolBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.full_mut()[..len]
    }
}

impl AsRef<[u8]> for PoolBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for PoolBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl fmt::Debug for PoolBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBuffer").field("len", &self.len).field("capacity", &self.pool.capacity).finish()
    }
}

impl Drop for PoolBuffer {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            // Queue has room for every buffer, so push only fails if the defensive
            // allocation path above ever ran; dropping the extra is then correct.
            let _ = self.pool.free.push(raw);
        }
        self.pool.permits.add_permits(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn buffers_are_page_aligned_and_sized() {
        let pool = BufferPool::new(2, 8192);
        let mut b = pool.try_acquire().unwrap();
        assert_eq!(b.len(), 8192);
        assert_eq!(b.as_ptr().align_offset(BUFFER_ALIGN), 0);
        b[0] = 1;
        b.set_len(10).unwrap();
        assert_eq!(b.len(), 10);
        assert!(b.set_len(8193).is_err());
        assert_eq!(b.full_mut().len(), 8192);
    }

    #[test]
    fn try_acquire_exhausts_and_recovers() {
        let pool = BufferPool::new(2, 16);
        let a = pool.try_acquire().unwrap();
        let _b = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
        assert_eq!(pool.available(), 0);
        drop(a);
        assert_eq!(pool.available(), 1);
        let c = pool.try_acquire().unwrap();
        assert_eq!(c.len(), 16, "len resets to capacity on reacquire");
    }

    #[tokio::test]
    async fn acquire_blocks_until_drop() {
        let pool = BufferPool::new(1, 64);
        let held = pool.acquire().await;
        let p2 = pool.clone();
        let waiter = tokio::spawn(async move { p2.acquire().await.capacity() });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "acquire must block while exhausted");
        drop(held);
        let cap = tokio::time::timeout(Duration::from_secs(5), waiter).await.unwrap().unwrap();
        assert_eq!(cap, 64);
        assert_eq!(pool.available(), 1);
    }
}
