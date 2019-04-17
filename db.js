const crypto = require('crypto');
const { promisify } = require('util');
const zlib = require('zlib');
const deltify = require('./deltify');
const levelup = require('levelup');
const rocksdb = require('rocksdb');

const FORMAT_NONE = 0x656e6f6e;
const FORMAT_DELT = 0x746c6564;
const FORMAT_ZLIB = 0x62696c7a;
const FORMAT_DLTZ = 0x7a746c64;

const MINOR_THRESHOLD = 512;
const COMPRESSION_THRESHOLD = 150;

/**
 * Hash a buffer.
 *
 * @param {Buffer} buffer Buffer to hash
 * @return {Buffer} 256-bit hash
 */
function calcHash(buffer) {
  const hash = crypto.createHash('sha256');
  hash.update(buffer);
  return hash.digest();
}

/**
 * Convert hash to normalised form.
 *
 * @param {any} hash hash either in String or Buffer form
 * @return {Buffer} 256-bit hash in Buffer form
 */
function verifyHash(hash) {
  hash = Buffer.from(hash, 'hex');
  if (hash.length != 32) throw new RangeError('hash must be 256-bit long');
  return hash;
}

// Format of file stored on disk:
//  +-----------+-------------+==================+
//  | file size | file format |...encoded file...|
//  +-----------+-------------+==================|
// The file size and format are fixed headers. The file size represent the number of bytes of the
// file is it is fully decoded. The file size is 4 bytes (LE) and file format is 4 bytes.
//
// If the file format is "none", no transformation is applied:
//    +==================+
//    |...file content...|
//    +==================+
// If the file format is "delt", the file is deltified:
//    +==============+========================+
//    | hash of base |...delta against base...|
//    +==============+========================+
// If the file format is "zlib" or "dltz", they are additionally compressed by zlib. Note that if
// the underlying store has compression by default (e.g. LevelDB), they should not be used.

class BlobDatabase {
  /**
   * Create a blob database
   *
   * @param {string} location Location of the database
   * @param {boolean} [options.readonly] If set to true, delta chain reduction will not happen
   *   when calling `get()`. Default to false.
   * @param {boolean} [options.verify] If set to true, hash will be re-computed and checked when
   *   calling `get()`. An exception will be thrown if it mismatches. Default to false.
   * @param {string} [options.compression] Determine which compression method to use. `none`
   *   indicates compression should be off; `transparent` means that the lower level key-value
   *   database will handle compressionl `zlib` indicates that zlib should be attempted before
   *   inserting into the database. Default to `transparent`.
   */
  constructor(location, options) {
    options = Object.assign({
      readonly: false,
      verify: false,
      compression: 'transparent',
    }, options);

    const db = typeof location != 'object' ? levelup(rocksdb(location), {
      readOnly: options.readonly,
      compression: options.compression == 'transparent',
    }) : location;
    this._options = options;
    this._db = db;
  }

  /**
   * Close the database. The object shouldn't be used anymore.
   *
   * @return {Promise}
   */
  close() {
    let promise = this._db.close();
    this._db = null;
    return promise;
  }

  /**
   * Retrieve a raw blob from database.
   *
   * @param {Buffer} hash 256-bit hash of the object to retrieve
   * @return {Promise<Buffer>} Returns the buffer for the blob
   */
  async _rawGet(hash) {
    // Read the data chunk from store
    let chunk;
    try {
      chunk = await this._db.get(hash);
    } catch (err) {
      if (!err.notFound) throw err;
      return null;
    }
    return chunk;
  }

  /**
   * Put a raw blob into database.
   *
   * @param {Buffer} hash 256-bit hash of the object to put
   * @param {Buffer} buffer contents of the blob
   * @return {Promise}
   */
  async _rawPut(hash, buffer) {
    if (buffer.length >= COMPRESSION_THRESHOLD) {
      switch (this._options.compression) {
        case 'zlib': {
          let compressed = await promisify(zlib.deflate)(buffer);
          // Fall to `none` format insertion
          if (compressed.length >= buffer.length) break;
          let file = Buffer.alloc(compressed.length + 8);
          file.writeUInt32LE(buffer.length, 0);
          file.writeUInt32LE(FORMAT_ZLIB, 4);
          compressed.copy(file, 8);
          return this._db.put(hash, file);
        }
      }
    }
    let file = Buffer.alloc(buffer.length + 8);
    file.writeUInt32LE(buffer.length, 0);
    file.writeUInt32LE(FORMAT_NONE, 4);
    buffer.copy(file, 8);
    return this._db.put(hash, file);
  }

  /**
   * Put a raw delta into database.
   *
   * @param {Buffer} hash 256-bit hash of the object to put
   * @param {Buffer} buffer contents of the blob
   * @param {Buffer} baseHash 256-bit hash of the base object
   * @param {Buffer} delta deltified contents
   * @param {Buffer} [file] deltified contents with additional space reserved header. Header will
   *   be modified.
   * @return {Promise}
   */
  async _deltaPut(hash, buffer, baseHash, delta, file) {
    if (delta.length >= COMPRESSION_THRESHOLD) {
      switch (this._options.compression) {
        case 'zlib': {
          let compressed = await promisify(zlib.deflate)(delta);
          // Fall to `delt` format insertion
          if (compressed.length >= delta.length) break;
          let file = Buffer.alloc(compressed.length + 40);
          file.writeUInt32LE(buffer.length, 0);
          file.writeUInt32LE(FORMAT_DLTZ, 4);
          baseHash.copy(file, 8);
          compressed.copy(file, 40);
          return this._db.put(hash, file);
        }
      }
    }
    if (file != null) {
      file = file.slice(0, delta.length + 40);
    } else {
      file = Buffer.alloc(delta.length + 40);
      delta.copy(file, 40);
    }
    file.writeUInt32LE(buffer.length, 0);
    file.writeUInt32LE(FORMAT_DELT, 4);
    baseHash.copy(file, 8);
    return this._db.put(hash, file);
  }

  /**
   * Put a blob into database.
   *
   * @param {Blob} blob blob to put
   * @return {Promise}
   */
  _blobPut(blob) {
    if (blob.delta != null) {
      return this._deltaPut(blob.hash, blob.buffer, blob.base.hash, blob.delta);
    } else {
      return this._rawPut(blob.hash, blob.buffer);
    }
  }

  /**
   * Convert raw blob to an object and decompress. Deltified blobs are not resolved.
   *
   * @param {Buffer} hash 256-bit hash of the object to retrieve
   * @param {Buffer} chunk Raw buffer
   * @return {Promise<Blob>} Returns the blob object
   */
  async _rawToBlob(hash, chunk) {
    // Read format. The file size can be used to optimise buffer allocation/growth.
    let fileSize = chunk.readUInt32LE(0);
    let format = chunk.readUInt32LE(4);

    switch (format) {
      case FORMAT_NONE: {
        let buffer = chunk.slice(8);
        if (buffer.length != fileSize) throw new Error('Length mismatch');
        return { hash, buffer, base: null, delta: null };
      }
      case FORMAT_ZLIB: {
        let buffer = await promisify(zlib.inflate)(chunk.slice(8));
        if (buffer.length != fileSize) throw new Error('Length mismatch');
        return { hash, buffer, base: null, delta: null };
      }
      case FORMAT_DELT: {
        // Retrieve the base hash
        let baseHash = Buffer.alloc(32);
        chunk.copy(baseHash, 0, 8, 40);
        return {
          hash: hash,
          buffer: { length: fileSize },
          base: { hash: baseHash },
          delta: chunk.slice(40),
        };
      }
      case FORMAT_DLTZ: {
        // Retrieve the base hash
        let baseHash = Buffer.alloc(32);
        chunk.copy(baseHash, 0, 8, 40);
        return {
          hash: hash,
          buffer: { length: fileSize },
          base: { hash: baseHash },
          delta: await promisify(zlib.inflate)(chunk.slice(40)),
        };
      }
      default: throw new RangeError('Unsupported format');
    }
  }

  /**
   * Retrieve a blob and decompress. Deltified blobs will be kept as is and not resolved.
   *
   * @param {Buffer} hash 256-bit hash of the object to retrieve
   * @return {Promise<Blob>} Returns the blob object
   */
  async _blobGet(hash) {
    // Read the data chunk from store
    let chunk = await this._rawGet(hash);
    if (chunk == null) return null;
    return this._rawToBlob(hash, chunk);
  }

  /**
   * Perform level-reduction.
   *
   * @param {Blob} blob The blob object to reduce.
   * @return {Promise<boolean>} Returns true if the blob is modified.
   */
  async _reduce(blob) {
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

    // Not a delta or a single level delta
    if (blob.base == null || blob.base.base == null) return false;

    if (blob.base.delta.length > MINOR_THRESHOLD &&
      blob.delta.length <= (blob.base.delta.length >> 1)) return false;

    let grandparent = blob.base.base;
    let file = Buffer.alloc(40 + (blob.buffer.length >> 1));
    let delta = deltify.encode(grandparent.buffer, blob.buffer, file.slice(40));
    // Better to un-deltify this blob.
    if (delta == null) {
      blob.delta = null;
      blob.base = null;
      await this._rawPut(blob.hash, blob.buffer);
      return true;
    }

    // Set fields and do recursive reduction. If the recursive reduction modified the object
    // then we don't need to write again.
    blob.delta = delta;
    blob.base = grandparent;
    if (await this._reduce(blob)) return true;

    await this._deltaPut(blob.hash, blob.buffer, grandparent.hash, delta, file);
    return true;
  }

  /**
   * Retrieve a blob, decompress and de-deltify. The base blob that it is deltified on is also
   * returned.
   *
   * @param {Buffer} hash 256-bit hash of the object to retrieve
   * @return {Promise<Blob>} Returns the blob object and all its bases.
   */
  async _chainGet(hash) {
    let blob = await this._blobGet(hash);
    if (blob == null) return null;

    // Resolve deltified blobs.
    if (blob.base != null) {
      // Recursive obtain parent
      let base = await this._chainGet(blob.base.hash);
      if (!base) {
        // In this case the parent might be corrupted or otherwise somehow missing.
        throw new Error(`Cannot find ${baseHash.toString('hex')} when trying to load ${hash.toString('hex')}`);
      }
      let body = Buffer.alloc(blob.buffer.length);
      body = deltify.decode(base.buffer, blob.delta, body);
      if (body.length != blob.buffer.length) throw new Error('Length mismatch');
      blob.buffer = body;
      blob.base = base;
      if (!this._options.readonly) await this._reduce(blob);
    }

    return blob;
  }

  /**
   * Retrieve a blob as buffer.
   *
   * @param {any} hash 256-bit hash of the object to retrieve
   * @return {Promise<Buffer>} Returns the blob
   */
  async get(hash) {
    hash = verifyHash(hash);
    let blob = await this._chainGet(hash);
    if (!blob) return null;
    if (this._options.verify) {
      if (calcHash(blob.buffer).compare(hash) != 0) throw new Error('Hash verification failed');
    }
    return blob.buffer;
  }

  /**
   * Insert a buffer to the database.
   *
   * @param {Buffer} buffer The blob to insert
   * @return {Promise<string>} Returns the 256-bit hash in hex form
   */
  async insert(buffer) {
    if (this._options.readonly) throw new Error('insert() cannot be called in readonly mode');
    const hash = calcHash(buffer);
    if ((await this._rawGet(hash)) != null) return hash.toString('hex');

    // Upon insertion, the data is by default stored as is without transformation applied.
    await this._rawPut(hash, buffer);
    return hash.toString('hex');
  }

  /**
   * Hint that two blobs are related, so there is a chance of compression.
   *
   * @param {Buffer} parent One of the blob to link, usually a larger one
   * @param {Buffer} child One of the blob to link, usually a smaller one
   * @returns {Promise}
   */
  async _link(parent, child) {
    // Double-check that hash are different
    let hashCompare = parent.hash.compare(child.hash);
    if (hashCompare == 0) return;

    // Make sure parent.length > child.length, or parent.hash < child.hash if length are equal.
    // This creates a canonical order, which prevents loops.
    if (parent.buffer.length < child.buffer.length ||
      (parent.buffer.length == child.buffer.length && hashCompare > 0))
      [parent, child] = [child, parent];

    // The file is too small to worth trying delta
    if (child.buffer.length <= MINOR_THRESHOLD) return;

    // If child is already delta-encoded, link parents first.
    if (child.base != null) {
      await this._link(parent, child.base);
      // In this case, still perform a delta, as it may generate better result if we
      // use `parent` as its parent instead of the current one.
    }

    // Generate delta. Only use it if it can save enough space.
    let deltaFile = Buffer.alloc(40 + (child.buffer.length >> 1));
    let delta = deltify.encode(parent.buffer, child.buffer, deltaFile.slice(40));
    if (delta == null) return;

    if (child.base != null) {
      // If we can't save any space, don't re-parent this child
      if (delta.length - child.delta.length > 0) return;
    }

    child.base = parent;
    child.delta = delta;

    // When linking nodes, apply ahead-of-time chain reduction
    // If reduction modifies the object, then we don't need to insert anymore.
    if (await this._reduce(child)) return;

    return this._deltaPut(child.hash, child.buffer, parent.hash, delta, deltaFile);
  }

  /**
   * Hint that two blobs are related, so there is a chance of compression.
   *
   * @param {Buffer} parentHash Hash of one of the blob to link, usually a larger one
   * @param {Buffer} childHash Hash of one of the blob to link, usually a smaller one
   * @returns {Promise}
   */
  async link(parentHash, childHash) {
    if (this._options.readonly) throw new Error('link() cannot be called in readonly mode');
    let [parent, child] = await Promise.all([
      this._chainGet(verifyHash(parentHash)),
      this._chainGet(verifyHash(childHash))
    ]);
    // Linking is a hint to the database, so failing to find it is not an error, just return.
    if (parent == null || child == null) return;
    return this._link(parent, child);
  }


  /**
   * Insert a blob and relate it to an existing blob. Logically it is equivalent to an insert
   * followed by a link, but it is superior in performance.
   *
   * @param {Buffer} parentHash Hash of the blob to link
   * @param {Buffer} buffer Buffer to insert
   * @returns {Promise<string>} 256-bit hash of buffer, in hex form.
   */
  async insertLink(parentHash, buffer) {
    if (this._options.readonly) throw new Error('link() cannot be called in readonly mode');
    const hash = calcHash(buffer);
    let [parent, child] = await Promise.all([
      this._chainGet(verifyHash(parentHash)),
      this._chainGet(hash)
    ]);
    // We don't need to insert just yet, we can perform linking first.
    if (child == null) {
      child = {
        hash,
        buffer,
        base: null,
        delta: null,
      }
    }
    // If we cannot find `parent`, then we can't invoke _link. In this case just let the
    // fall-through code insert it normally into the database.
    if (parent != null)
      await this._link(parent, child);
    // Only when delta is empty (which means link does write anything to child.hash) and when
    // the buffer is the supplied one (otherwise it is loaded from database, so we don't need to
    // write again).
    if (child.delta == null && child.buffer == buffer) {
      await this._rawPut(hash, buffer);
    }
    return hash.toString('hex');
  }
}

exports.hash = calcHash;
exports.BlobDatabase = BlobDatabase;
