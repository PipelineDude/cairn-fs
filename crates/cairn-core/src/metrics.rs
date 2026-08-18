//! Backup statistics (extracted from lib.rs 2026-08-16: cairn-core was a
//! single 4300-line file; metrics are a self-contained unit with no
//! dependency on CairnEngine internals).

/// Per-operation backup statistics, tracked via atomics on `CairnEngine`.
/// The backup handler snapshots counters before/after to compute deltas.
pub struct BackupStats {
    pub dedup_hits: std::sync::atomic::AtomicUsize,
    pub new_chunks: std::sync::atomic::AtomicUsize,
    pub bytes_deduped: std::sync::atomic::AtomicUsize,
    pub bytes_written: std::sync::atomic::AtomicUsize,
    pub files_processed: std::sync::atomic::AtomicUsize,
    pub files_skipped: std::sync::atomic::AtomicUsize,
}

impl BackupStats {
    pub fn new() -> Self {
        Self {
            dedup_hits: std::sync::atomic::AtomicUsize::new(0),
            new_chunks: std::sync::atomic::AtomicUsize::new(0),
            bytes_deduped: std::sync::atomic::AtomicUsize::new(0),
            bytes_written: std::sync::atomic::AtomicUsize::new(0),
            files_processed: std::sync::atomic::AtomicUsize::new(0),
            files_skipped: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn snapshot(&self) -> BackupStatsSnapshot {
        BackupStatsSnapshot {
            dedup_hits: self.dedup_hits.load(std::sync::atomic::Ordering::Relaxed),
            new_chunks: self.new_chunks.load(std::sync::atomic::Ordering::Relaxed),
            bytes_deduped: self
                .bytes_deduped
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_written: self
                .bytes_written
                .load(std::sync::atomic::Ordering::Relaxed),
            files_processed: self
                .files_processed
                .load(std::sync::atomic::Ordering::Relaxed),
            files_skipped: self
                .files_skipped
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.dedup_hits
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.new_chunks
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.bytes_deduped
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.bytes_written
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.files_processed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.files_skipped
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for BackupStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BackupStatsSnapshot {
    pub dedup_hits: usize,
    pub new_chunks: usize,
    pub bytes_deduped: usize,
    pub bytes_written: usize,
    pub files_processed: usize,
    pub files_skipped: usize,
}

impl BackupStatsSnapshot {
    pub fn delta(&self, before: &BackupStatsSnapshot) -> BackupStatsDelta {
        BackupStatsDelta {
            dedup_hits: self.dedup_hits.saturating_sub(before.dedup_hits),
            new_chunks: self.new_chunks.saturating_sub(before.new_chunks),
            bytes_deduped: self.bytes_deduped.saturating_sub(before.bytes_deduped),
            bytes_written: self.bytes_written.saturating_sub(before.bytes_written),
            files_processed: self.files_processed.saturating_sub(before.files_processed),
            files_skipped: self.files_skipped.saturating_sub(before.files_skipped),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BackupStatsDelta {
    pub dedup_hits: usize,
    pub new_chunks: usize,
    pub bytes_deduped: usize,
    pub bytes_written: usize,
    pub files_processed: usize,
    pub files_skipped: usize,
}

impl std::fmt::Display for BackupStatsDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_chunks = self.dedup_hits + self.new_chunks;
        let dedup_ratio = if total_chunks > 0 {
            self.dedup_hits as f64 / total_chunks as f64 * 100.0
        } else {
            0.0
        };
        let comp_ratio = if self.bytes_written > 0 && self.bytes_deduped > 0 {
            self.bytes_deduped as f64 / self.bytes_written as f64
        } else {
            0.0
        };
        write!(
            f,
            "files: {} processed, {} skipped | chunks: {} new, {} deduped ({:.1}%) | \
             bytes: {} written, {} deduped",
            self.files_processed,
            self.files_skipped,
            self.new_chunks,
            self.dedup_hits,
            dedup_ratio,
            human_bytes(self.bytes_written),
            human_bytes(self.bytes_deduped),
        )?;
        if comp_ratio > 1.0 {
            write!(f, " | compression: {:.1}x", comp_ratio)?;
        }
        Ok(())
    }
}

pub fn human_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
