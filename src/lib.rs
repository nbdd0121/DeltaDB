use byteorder::{ByteOrder, LE};
use bytes::Bytes;
use parking_lot::Mutex;
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub mod delta;

/// Hash of a blob.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hash([u8; 32]);

/// Error parsing hash from string.
#[derive(Clone, Copy, Debug)]
pub struct HashParseError;

impl std::str::FromStr for Hash {
    type Err = HashParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut slice = [0; 32];
        match hex::decode_to_slice(s, &mut slice) {
            Ok(_) => Ok(Hash(slice)),
            Err(_) => Err(HashParseError),
        }
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Compression options of the database.
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub enum Compression {
    /// Turn off compression at all. This will cause the compression of underlying storage to be
    /// turned off as well.
    None,
    /// Use the underlying storage for compression, but does perform additional compression on
    /// top.
    Transparent,
    /// Use zlib to compress data if it reduces size. The underlying storage compression is turned
    /// off to prevent performance loss from trying double compression.
    Zlib,
}

/// Options of the database.
#[derive(Clone)]
pub struct Options {
    readonly: bool,
    verify: bool,
    compression: Compression,
}

impl Options {
    /// Create a `Option` with default configuration.
    pub fn new() -> Self {
        Self {
            readonly: false,
            verify: false,
            compression: Compression::Transparent,
        }
    }

    /// Specifies whether write access should be allowed.
    pub fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }

    /// Specifies whether the content hash should be verified on retrieval, to capture potential
    /// issues in storage.
    pub fn set_verify_on_retrieval(&mut self, verify: bool) {
        self.verify = verify;
    }

    /// Specifies the compression mechanism to be used.
    pub fn set_compression(&mut self, compression: Compression) {
        self.compression = compression;
    }
}

impl Default for Options {
    fn default() -> Self {
        Options::new()
    }
}

/// Compute hash of a buffer.
pub fn calc_hash(buffer: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.input(buffer);

    let mut hash = [0; 32];
    hash.copy_from_slice(&hasher.result()[..]);
    Hash(hash)
}

/// A delta database.
pub struct Database {
    db: rocksdb::DB,
    options: Options,
}

const FORMAT_NONE: u32 = 0x656e6f6e;
const FORMAT_DELT: u32 = 0x746c6564;
const FORMAT_ZLIB: u32 = 0x62696c7a;
const FORMAT_DLTZ: u32 = 0x7a746c64;

const MINOR_THRESHOLD: usize = 512;
const COMPRESSION_THRESHOLD: usize = 150;

fn compress(src: &[u8], buffer: &mut [u8]) -> Result<usize, ()> {
    let mut compress = flate2::Compress::new(Default::default(), true);
    let status = compress
        .compress(src, buffer, flate2::FlushCompress::Finish)
        .unwrap();
    if status != flate2::Status::StreamEnd {
        return Err(());
    }
    Ok(compress.total_out() as _)
}

struct Delta {
    base: Arc<Blob>,
    delta: Vec<u8>,
}

struct Blob {
    hash: Hash,
    buffer: Bytes,
    base: Mutex<Option<Delta>>,
}

enum RawBlob {
    Plain(Vec<u8>),
    Delta(usize, Hash, Vec<u8>),
}

fn wrap_err(err: rocksdb::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

impl Database {
    fn open_path(path: &Path, opts: &Options) -> io::Result<Database> {
        let mut opt = rocksdb::Options::default();
        opt.create_if_missing(true);
        if opts.compression == Compression::Transparent {
            opt.set_compression_type(rocksdb::DBCompressionType::Snappy);
        }
        let db = rocksdb::DB::open(&opt, path).map_err(wrap_err)?;
        Ok(Database {
            db,
            options: opts.clone(),
        })
    }

    /// Open a database with given path and options.
    pub fn open(path: impl AsRef<Path>, opts: &Options) -> io::Result<Database> {
        Self::open_path(path.as_ref(), opts)
    }

    // Retrieve a raw blob from database.
    fn raw_get(&self, hash: &Hash) -> io::Result<Option<RawBlob>> {
        let chunk = match self.db.get_pinned(&hash.0).map_err(wrap_err)? {
            None => return Ok(None),
            Some(v) => v,
        };
        let file_size = LE::read_u32(&chunk[0..]) as usize;
        let format = LE::read_u32(&chunk[4..]);
        let raw_blob = match format {
            FORMAT_NONE => RawBlob::Plain(chunk[8..].to_owned()),
            FORMAT_ZLIB => {
                let mut buffer = Vec::with_capacity(file_size);
                let mut decompress = flate2::Decompress::new(true);
                let status = decompress
                    .decompress_vec(&chunk[8..], &mut buffer, flate2::FlushDecompress::Finish)
                    .unwrap();
                assert_eq!(status, flate2::Status::StreamEnd);
                RawBlob::Plain(buffer)
            }
            FORMAT_DELT => {
                let mut base_hash = Hash([0; 32]);
                base_hash.0.copy_from_slice(&chunk[8..40]);
                RawBlob::Delta(file_size, base_hash, chunk[40..].to_owned())
            }
            FORMAT_DLTZ => {
                let mut base_hash = Hash([0; 32]);
                base_hash.0.copy_from_slice(&chunk[8..40]);

                let mut buffer = Vec::with_capacity(file_size / 2);
                let mut decompress = flate2::Decompress::new(true);
                let status = decompress
                    .decompress_vec(&chunk[40..], &mut buffer, flate2::FlushDecompress::Finish)
                    .unwrap();
                assert_eq!(status, flate2::Status::StreamEnd);
                RawBlob::Delta(file_size, base_hash, buffer)
            }
            _ => unreachable!("unknown format"),
        };
        Ok(Some(raw_blob))
    }

    // Retrieve a raw blob from database.
    fn blob_get(&self, hash: &Hash) -> io::Result<Option<Arc<Blob>>> {
        let mut stack = Vec::new();

        // blob_get must not use recursion to avoid stack overflow before blobs are normalized
        // in depth. We use two passes, one pass to fetch from child to parent, and one pass back.
        let mut hash = *hash;

        let mut base_blob = loop {
            match self.raw_get(&hash)? {
                None => {
                    if stack.is_empty() {
                        return Ok(None);
                    }
                    unreachable!("parent does not exist");
                }
                Some(RawBlob::Plain(buffer)) => {
                    break Arc::new(Blob {
                        hash,
                        buffer: buffer.into(),
                        base: Mutex::new(None),
                    });
                }
                Some(RawBlob::Delta(file_size, base_hash, delta)) => {
                    stack.push((hash, file_size, delta));
                    hash = base_hash;
                }
            }
        };

        while let Some((hash, file_size, delta)) = stack.pop() {
            let mut buffer = Vec::with_capacity(file_size);
            delta::apply_delta(&base_blob.buffer, &delta, &mut buffer).unwrap();
            base_blob = Arc::new(Blob {
                hash,
                buffer: buffer.into(),
                base: Mutex::new(Some(Delta {
                    base: base_blob,
                    delta,
                })),
            });
            if !self.options.readonly {
                self.reduce(&base_blob)?;
            }
        }

        Ok(Some(base_blob))
    }

    /// Put a raw blob into the database.
    fn blob_put(&self, blob: &Blob) -> io::Result<()> {
        let mut file = Vec::with_capacity(blob.buffer.len() + 8);
        file.extend_from_slice(&(blob.buffer.len() as u32).to_le_bytes());

        let guard = blob.base.lock();
        match guard.as_ref() {
            Some(delta) => {
                file.extend_from_slice(&FORMAT_DELT.to_le_bytes());
                file.extend_from_slice(&delta.base.hash.0);

                if delta.delta.len() >= COMPRESSION_THRESHOLD
                    && self.options.compression == Compression::Zlib
                {
                    unsafe { file.set_len(file.capacity()) };
                    if let Ok(size) = compress(&delta.delta, &mut file[40..]) {
                        file.truncate(size + 40);
                        file[4..8].copy_from_slice(&FORMAT_DLTZ.to_le_bytes());
                    } else {
                        file.truncate(40);
                        file.extend_from_slice(&delta.delta);
                    }
                } else {
                    file.extend_from_slice(&delta.delta);
                }
            }
            None => {
                file.extend_from_slice(&FORMAT_NONE.to_le_bytes());

                if blob.buffer.len() >= COMPRESSION_THRESHOLD
                    && self.options.compression == Compression::Zlib
                {
                    unsafe { file.set_len(file.capacity()) };
                    if let Ok(size) = compress(&blob.buffer, &mut file[8..]) {
                        file.truncate(size + 8);
                        file[4..8].copy_from_slice(&FORMAT_ZLIB.to_le_bytes());
                    } else {
                        file.truncate(8);
                        file.extend_from_slice(&blob.buffer);
                    }
                } else {
                    file.extend_from_slice(&blob.buffer);
                }
            }
        }
        drop(guard);

        self.db.put(&blob.hash.0, &file).map_err(wrap_err)
    }

    /// Perform level-reduction. Returns true if the blob is modified.
    fn reduce(&self, blob: &Blob) -> io::Result<bool> {
        /*
         * To avoid very long chains of deltified blobs, we attempt to reduce the length of delta
         * chain.  Assuming the following case:
         *   A --> B --> C
         * We should remove B from chain if it does not sacrifice much.  Notice that we will need to
         * determine whether we should perform this operation on each access, therefore we must be able
         * to determine whether any action should be taken without expensive computation.
         *
         * We do this in two ways:
         * 1) We observe if B is a minor edit to C, then delta of A upon C should be small as well.
         *    If B is a major edit on the otherhand, then A probably will not deltify well based on C.
         *    To determine whether B is a minor edit, we just look on the size of its delta on C. This
         *    heuristic performs really well and have almost no space loss.
         * 2) If we only have 1) applied, then we can still get very long delta chains.  We therefore
         *    also enforce stricter limits:
         *    * A delta must be smaller than half of its original size.  If a delta is larger than half
         *      of original size, it means that it shares only less than half contents with its parent,
         *      so we'd better not use delta at all.  This restriction comes with small space loss.
         *    * A delta of delta must be less than half the size of the base delta.  This is not
         *      intuitive, and has signifcant space loss.  However, this requirement will allow us to
         *      prove that the total disk load we need for accessing an item is smaller than twice
         *      the largest blob on the chain.  Combining with the requirement on 1), it essentially
         *      limits the chain length to clog2(|max blob| / |minor threshold|)). If max blob isze
         *      is 64K and minor threshold is 512, the chain will not be longer than 7.
         */

        let mut mutated = false;
        loop {
            let mut lock_guard = blob.base.lock();
            let lock = match *lock_guard {
                Some(ref mut v) => v,
                // Not a delta
                None => break,
            };

            let base = lock.base.clone();
            let mut base_lock_guard = base.base.lock();
            let base_lock = match *base_lock_guard {
                Some(ref mut v) => v,
                // Single level delta
                None => break,
            };

            // Size constraints are satisified.
            if base_lock.delta.len() > MINOR_THRESHOLD
                && lock.delta.len() <= base_lock.delta.len() / 2
            {
                break;
            }

            drop(lock_guard);
            let grandparent = base_lock.base.clone();
            drop(base_lock_guard);

            // We violated the constraints, so we are committed to make modifications.
            mutated = true;

            let mut delta = Vec::with_capacity(blob.buffer.len() / 2);
            delta::calc_delta(&grandparent.buffer, &blob.buffer, &mut delta);
            // Better to un-deltify this blob
            if delta.len() > blob.buffer.len() / 2 {
                *blob.base.lock() = None;
                break;
            }

            // Set fields and do recursive reduction. If the recursive reduction modified the object
            // then we don't need to write again.
            *blob.base.lock() = Some(Delta {
                delta,
                base: grandparent,
            });
        }

        if mutated {
            self.blob_put(&blob)?;
        }
        Ok(mutated)
    }

    fn link_blob(&self, mut parent: Arc<Blob>, mut child: Arc<Blob>) -> io::Result<()> {
        let ord = parent.hash.cmp(&child.hash);
        if ord == std::cmp::Ordering::Equal {
            return Ok(());
        }

        // Make sure parent.length > child.length, or parent.hash < child.hash if length are equal.
        // This creates a canonical order, which prevents loops.
        if parent.buffer.len() < child.buffer.len()
            || (parent.buffer.len() == child.buffer.len() && ord == std::cmp::Ordering::Greater)
        {
            std::mem::swap(&mut parent, &mut child);
        }

        // The file is too small to worth trying delta
        if child.buffer.len() <= MINOR_THRESHOLD {
            return Ok(());
        }

        let mut lock = child.base.lock();

        // If child is already delta-encoded, link parents first.
        if let Some(base) = &*lock {
            // This recursion is fine, it wouldn't cause stack overflow, becauses blobs are normalized already.
            self.link_blob(parent.clone(), base.base.clone())?;
            // In this case, still perform a delta, as it may generate better result if we
            // use `parent` as its parent instead of the current one.
        }

        // Generate delta. Only use it if it can save enough space.
        let mut delta = Vec::with_capacity(child.buffer.len() / 2);
        delta::calc_delta(&parent.buffer, &child.buffer, &mut delta);
        if delta.len() > child.buffer.len() / 2 {
            return Ok(());
        }

        if let Some(base) = &*lock {
            // If we can't save any space, don't re-parent this child
            if delta.len() > base.delta.len() {
                return Ok(());
            }
        }

        *lock = Some(Delta {
            base: parent.clone(),
            delta,
        });
        std::mem::drop(lock);

        if self.reduce(&child)? {
            return Ok(());
        }

        self.blob_put(&child)?;
        Ok(())
    }

    pub fn get(&self, hash: &Hash) -> io::Result<Option<Bytes>> {
        Ok(match self.blob_get(hash)? {
            None => None,
            Some(v) => {
                if self.options.verify {
                    assert_eq!(hash, &calc_hash(&v.buffer), "Hash verification failed");
                }
                Some(v.buffer.clone())
            }
        })
    }

    pub fn insert(&self, buffer: Bytes) -> io::Result<Hash> {
        assert!(!self.options.readonly, "Database is readonly");
        let hash = calc_hash(&buffer);

        if self.db.get_pinned(&hash.0).map_err(wrap_err)?.is_some() {
            return Ok(hash);
        }

        let blob = Arc::new(Blob {
            hash,
            buffer,
            base: Mutex::new(None),
        });

        self.blob_put(&blob)?;
        Ok(hash)
    }

    pub fn link(&self, parent: &Hash, child: &Hash) -> io::Result<()> {
        assert!(!self.options.readonly, "Database is readonly");
        match (self.blob_get(parent)?, self.blob_get(child)?) {
            (Some(pblob), Some(clob)) => self.link_blob(pblob, clob),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
fn _assert_send<F: Send>(_f: &F) {}
