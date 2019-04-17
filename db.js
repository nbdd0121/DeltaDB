const crypto = require('crypto');
const { promisify } = require('util');
const zlib = require('zlib');
const deltify = require('./deltify');
const levelup = require('levelup');
const leveldown = require('leveldown');

const FORMAT_NONE = 0x656e6f6e;
const FORMAT_DELT = 0x746c6564;
const FORMAT_ZLIB = 0x62696c7a;
const FORMAT_DLTZ = 0x7a746c64;

const PATH_COMPRESSION_LOSS_THRESHOLD = 512;
const DELTIFY_GAIN_THRESHOLD = 4096;

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
  constructor(location, options) {
    options = Object.assign({
      readonly: false,
    }, options);

    const db = levelup(typeof location != 'object' ? leveldown(location) : location);
    this._options = options;
    this._db = db;
  }

  /**
   * Close the database. The object shouldn't be used anymore.
   *
   * @method
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
   * @method
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
   * Retrieve a blob and decompress. Deltified blobs will be kept as is and not resolved.
   *
   * @method
   * @param {Buffer} hash 256-bit hash of the object to retrieve
   * @return {Promise<Blob>} Returns the blob object
   */
  async _blobGet(hash) {
    // Read the data chunk from store
    let chunk = await this._rawGet(hash);
    if (chunk == null) return null;

    // Read format. The file size can be used to optimise buffer allocation/growth.
    let fileSize = chunk.readUInt32LE(0);
    let format = chunk.readUInt32LE(4);

    switch (format) {
      case FORMAT_NONE: return {
        hash: hash,
        buffer: chunk.slice(8),
        base: null,
        delta: null,
      };
      case FORMAT_ZLIB: return {
        hash: hash,
        buffer: await promisify(zlib.inflate)(chunk.slice(8)),
        base: null,
        delta: null,
      };
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
   * Perform a single-step path compression.
   *
   * @method
   * @param {Blob} blob The blob object to compress.
   * @return {Promise<boolean>} Returns true if the blob is modified.
   */
  async _compress(blob) {
    // Not a delta
    if (blob.base == null) return false;

    // Normally we shouldn't need to do anything for single-level delta. However path compression
    // may add cost to an extent that it's better to just un-deltify a blob at all. We handle this
    // case here.
    if (blob.base.base == null) {
      if (blob.buffer.length - blob.delta.length < DELTIFY_GAIN_THRESHOLD) {
        blob.delta = null;
        blob.base = null;
        let file = Buffer.alloc(blob.buffer.length + 8);
        file.writeInt32LE(blob.buffer.length, 0);
        file.writeInt32LE(FORMAT_NONE, 4);
        blob.buffer.copy(file, 8);
        await this._db.put(blob.hash, file);
        return true;
      }
      return false;
    }

    let grandparent = blob.base.base;
    let newDeltaFile = Buffer.alloc(40 + blob.delta.length + PATH_COMPRESSION_LOSS_THRESHOLD);
    let newDelta = deltify.encode(grandparent.buffer, blob.buffer, newDeltaFile.slice(40));
    // Path compression isn't worthwhile.
    if (newDelta == null) return false;

    // Set fields and do recursive compression. If the recursive compression modified the object
    // then we don't need to write again.
    blob.delta = newDelta;
    blob.base = grandparent;
    if (await this._compress(blob)) return true;

    newDeltaFile = newDeltaFile.slice(0, newDelta.length + 40);
    newDeltaFile.writeInt32LE(blob.buffer.length, 0);
    newDeltaFile.writeInt32LE(FORMAT_DELT, 4);
    grandparent.hash.copy(newDeltaFile, 8);
    await this._db.put(blob.hash, newDeltaFile);
    return true;
  }

  /**
   * Retrieve a blob, decompress and de-deltify. The base blob that it is deltified on is also
   * returned.
   *
   * @method
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
        console.warn(`Cannot find ${baseHash.toString('hex')} when trying to load ${baseHash.toString('hex')}`);
        return null;
      }
      let body = Buffer.alloc(blob.buffer.length);
      body = deltify.decode(base.buffer, blob.delta, body);
      if (body.length != blob.buffer.length) throw new Error('Length mismatch');
      blob.buffer = body;
      blob.base = base;
      if (!this._options.readonly) await this._compress(blob);
    }

    return blob;
  }

  /**
   * Retrieve a blob as buffer.
   *
   * @method
   * @param {any} hash 256-bit hash of the object to retrieve
   * @return {Promise<Buffer>} Returns the blob
   */
  async get(hash) {
    hash = verifyHash(hash);
    let blob = await this._chainGet(hash);
    return blob ? blob.buffer : null;
  }

  /**
   * Insert a buffer to the database.
   *
   * @method
   * @param {Buffer} buffer The blob to insert
   * @return {Promise<string>} Returns the 256-bit hash in hex form
   */
  async insert(buffer) {
    if (this._options.readonly) throw new Error('insert() cannot be called in readonly mode');
    const hash = calcHash(buffer);
    if ((await this._rawGet(hash)) != null) return hash.toString('hex');

    // Upon insertion, the data is by default stored as is without transformation applied.
    let file = Buffer.alloc(buffer.length + 8);
    file.writeInt32LE(buffer.length, 0);
    file.writeInt32LE(FORMAT_NONE, 4);
    buffer.copy(file, 8);
    await this._db.put(hash, file);
    return hash.toString('hex');
  }

  /**
   * Hint that two blobs are related, so there is a chance of compression.
   *
   * @method
   * @param {Buffer} parent One of the blob to link, usually a larger one
   * @param {Buffer} child One of the blob to link, usually a smaller one
   * @returns {Promise<boolean>}
   */
  async _link(parent, child) {
    // Double-check that hash are different
    let hashCompare = parent.hash.compare(child.hash);
    if (hashCompare == 0) return false;

    // Make sure parent.length > child.length, or parent.hash < child.hash if length are equal.
    // This creates a canonical order, which prevents loops.
    if (parent.buffer.length < child.buffer.length ||
      (parent.buffer.length == child.buffer.length && hashCompare > 0))
      [parent, child] = [child, parent];

    // The file is too small to worth trying delta
    if (child.buffer.length <= DELTIFY_GAIN_THRESHOLD) return false;

    // If child is already delta-encoded, link parents first.
    if (child.base != null) {
      await this._link(parent, child.base);
      // In this case, still perform a delta, as it may generate better result if we sway child to
      // use `parent` as its parent instead of the current one.
    }

    // Generate delta. Only use it if it can save enough space.
    let deltaFile = Buffer.alloc(40 + child.buffer.length - DELTIFY_GAIN_THRESHOLD);
    let delta = deltify.encode(parent.buffer, child.buffer, deltaFile.slice(40));
    if (delta == null) return false;

    if (child.base != null) {
      // If we can't save any space, don't re-parent this child
      if (delta.length - child.delta.length > 0) return false;
    }

    child.base = parent;
    child.delta = delta;

    // When linking nodes, apply ahead-of-time path compression
    // If compression modifies the object, then we don't need to insert anymore.
    if (await this._compress(child)) return true;

    // Generate required headers
    deltaFile = deltaFile.slice(0, delta.length + 40);
    deltaFile.writeInt32LE(child.buffer.length, 0);
    deltaFile.writeInt32LE(FORMAT_DELT, 4);
    parent.hash.copy(deltaFile, 8);
    await this._db.put(child.hash, deltaFile);
    return true;
  }

  /**
   * Hint that two blobs are related, so there is a chance of compression.
   *
   * @method
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
   * @method
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
      let file = Buffer.alloc(buffer.length + 8);
      file.writeInt32LE(buffer.length, 0);
      file.writeInt32LE(FORMAT_NONE, 4);
      buffer.copy(file, 8);
      await this._db.put(hash, file);
    }
    return hash.toString('hex');
  }
}

exports.hash = calcHash;
exports.BlobDatabase = BlobDatabase;
