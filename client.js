/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2019, Gary Guo
 */
const crypto = require('crypto');
const fetch = require('isomorphic-fetch');

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

class BlobDatabase {
  /**
   * Create a helper with same public interface with BlobDatabase, but works over HTTP.
   *
   * @param {string} url Base url of the remote blob database server.
   */
  constructor(url) {
    this._url = url;
  }

  /**
   * Close the database. The object shouldn't be used anymore.
   *
   * @return {Promise}
   */
  close() {
    this._url = null;
    return Promise.resolve();
  }

  /**
   * Retrieve a blob as buffer.
   *
   * @param {any} hash 256-bit hash of the object to retrieve
   * @return {Promise<Buffer>} Returns the blob
   */
  async get(hash) {
    hash = verifyHash(hash);
    let resp = await fetch(this._url + hash.toString('hex'));
    if (!resp.ok) {
      if (resp.status == 404) return null;
      throw new Error(await resp.text());
    }
    return resp.buffer();
  }

  /**
   * Insert a buffer to the database.
   *
   * @param {Buffer} buffer The blob to insert
   * @return {Promise<string>} Returns the 256-bit hash in hex form
   */
  async insert(buffer) {
    const hash = calcHash(buffer);
    let resp = await fetch(this._url + hash.toString('hex'), {
      method: 'PUT',
      body: buffer,
    });
    if (!resp.ok) {
      throw new Error(await resp.text());
    }
    return hash.toString('hex');
  }

  /**
   * Hint that two blobs are related, so there is a chance of compression.
   *
   * @param {Buffer} parentHash Hash of one of the blob to link, usually a larger one
   * @param {Buffer} childHash Hash of one of the blob to link, usually a smaller one
   * @returns {Promise}
   */
  async link(parentHash, childHash) {
    parentHash = verifyHash(parentHash);
    childHash = verifyHash(childHash);
    let resp = await fetch(this._url + childHash.toString('hex') + '?link=' + parentHash.toString('hex'), {
      method: 'PATCH',
    });
    if (!resp.ok) {
      throw new Error(await resp.text());
    }
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
    const hash = calcHash(buffer);
    parentHash = verifyHash(parentHash);
    let resp = await fetch(this._url + hash.toString('hex') + '?link=' + parentHash.toString('hex'), {
      method: 'PUT',
      body: buffer,
    });
    if (!resp.ok) {
      throw new Error(await resp.text());
    }
    return hash.toString('hex');
  }
}

exports.hash = calcHash;
exports.BlobDatabase = BlobDatabase;
