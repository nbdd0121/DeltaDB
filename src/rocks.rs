//! A thin wrapper around rocksdb to provide async

use std::io::Result;
use std::path::Path;
use std::sync::Arc;

pub struct AsyncRocks {
    inner: Arc<Inner>,
}

struct Inner {
    db: rocksdb::DB,
}

// Slice must comes before Arc so it's destroyed first
pub struct ReadSlice(rocksdb::DBPinnableSlice<'static>, Arc<Inner>);

unsafe impl Send for ReadSlice {}
unsafe impl Sync for ReadSlice {}

impl std::ops::Deref for ReadSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn wrap_error<T>(result: std::result::Result<T, rocksdb::Error>) -> Result<T> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

impl AsyncRocks {
    pub fn open(path: impl AsRef<Path>, opts: &rocksdb::Options) -> Result<AsyncRocks> {
        let db = wrap_error(rocksdb::DB::open(&opts, path))?;
        Ok(AsyncRocks {
            inner: Arc::new(Inner { db }),
        })
    }

    pub async fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<ReadSlice>> {
        let inner = self.inner.clone();
        let key = key.as_ref().to_owned();

        tokio::task::spawn_blocking(move || {
            let dbvec = match wrap_error(inner.db.get_pinned(key)) {
                Err(err) => return Err(err),
                Ok(None) => return Ok(None),
                Ok(Some(v)) => v,
            };
            Ok(Some({
                // Safe because ReadSlice will own the Arc, so DBPinnableSlice will live long
                // enoguh.
                let slice =
                    unsafe { std::mem::transmute::<_, rocksdb::DBPinnableSlice<'static>>(dbvec) };
                ReadSlice(slice, inner)
            }))
        })
        .await
        .unwrap()
    }

    pub async fn put(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<()> {
        let inner = self.inner.clone();
        // Some very inefficient clones, but no better way for now.
        let key = key.as_ref().to_owned();
        let value = value.as_ref().to_owned();

        tokio::task::spawn_blocking(move || wrap_error(inner.db.put(key, value)))
            .await
            .unwrap()
    }
}
