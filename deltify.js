/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2019, Gary Guo
 */

// Binary delta encoding/decoding algorithm.
//
// References:
// https://www.fossil-scm.org/index.html/doc/trunk/www/delta_encoder_algorithm.wiki
// https://en.wikipedia.org/wiki/Rolling_hash

const HASH_LENGTH = 16;
const HASH_ROLL_MAGIC = (() => {
  let result = 1;
  for (let i = 0; i < HASH_LENGTH; i++) {
    result = (result * 31) | 0;
  }
  return result;
})();

/**
 * Cyclic polynomial hashing function, hash `HASH_LENGTH` bytes.
 *
 * @param {Buffer} buffer Buffer to hash
 * @param {number} idx Index to start hashing
 * @return {number} Calculated hash
 */
function calcHash(buffer, idx) {
  let hash = 0;
  for (let i = 0; i < HASH_LENGTH; i++) {
    hash = (hash * 31) | 0;
    hash = (hash + buffer.readUInt8(idx + i)) | 0;
  }
  return hash;
}

/**
 * Rolls the hash one byte to the next.
 *
 * @param {number} oldHash `calcHash(buffer, idx - 1)`
 * @param {Buffer} buffer Buffer to hash
 * @param {number} idx Index to start hashing
 * @return {number} Calculated hash
 */
function rollHash(oldHash, buffer, idx) {
  let hash = (oldHash * 31) | 0;
  hash = (hash - (HASH_ROLL_MAGIC * buffer.readUInt8(idx - 1)) | 0) | 0;
  hash = (hash + buffer.readUInt8(idx + HASH_LENGTH - 1)) | 0;
  return hash;
}

/**
 * Delta encode
 *
 * @param {Buffer} oldText Base of delta
 * @param {Buffer} newText Buffer to encode
 * @param {Buffer} [buffer] Pre-allocated buffer to store the delta. If not supplied, a buffer of
 *  length `oldText.length` will be allocated.
 * @return {Buffer} Delta encoding of newText. It will be `buffer` sliced to correct length. If
 *  the delta encoding does not fit into `buffer`, `null` will be returned.
 */
function encode(oldText, newText, buffer) {
  // Build hash table for oldText for speed up
  const hashmap = new Map();
  // Calculate from back to front to prioritise blocks in the beginning, as
  // * it is searched first, and
  // * in repetitive cases, it can capture longer duplication
  for (let i = ((oldText.length / HASH_LENGTH - 1) | 0) * HASH_LENGTH; i >= 0; i -= HASH_LENGTH) {
    let hash = calcHash(oldText, i);
    hashmap.set(hash, i);
  }

  // Allocate buffer, with extra space to simply boundary check.
  if (!buffer) buffer = Buffer.alloc(newText.length);
  let bufferLen = 0;

  // Last emit index tracks the earliest possible location that we can go back.
  let lastEmitIndex = 0;
  let index = 0;

  // Set index to a small number so first iteration always recalculate it.
  let hashIndex = -100;
  let hash = 0;

  while (index <= newText.length - HASH_LENGTH) {
    // Recalculate or rolls the hash based on index
    hash = hashIndex + 1 == index ? rollHash(hash, newText, index) : calcHash(newText, index);
    hashIndex = index;
    let ptr = hashmap.get(hash);
    // Either it does not match or this is a hash collision.
    if (ptr == null || oldText.compare(newText, index, index + HASH_LENGTH, ptr, ptr + HASH_LENGTH) != 0) {
      index++;
      continue;
    }

    // First backtrack to see if we can find extra matches, but we cannot go beyond lastEmitIndex
    let len = HASH_LENGTH;
    while (index > lastEmitIndex && oldText[ptr - 1] == newText[index - 1]) {
      ptr--;
      index--;
      len++;
    }
    // Search forward to match as long as possible.
    // The maximum length cannot exceed 32768, as we use negative length numbers to denote ranges
    const lenMax = Math.min(oldText.length - ptr, newText.length - index);
    while (len < lenMax && oldText[ptr + len] == newText[index + len]) len++;

    // Emit all literals as is.
    let copyLen = index - lastEmitIndex;
    if (copyLen) {
      // The buffer would overflow, abort.
      if (bufferLen + copyLen + 4 > buffer.length) return null;
      // Positive number encodes literal copy.
      buffer.writeInt32LE(copyLen, bufferLen);
      bufferLen += 4;
      newText.copy(buffer, bufferLen, lastEmitIndex, index);
      bufferLen += copyLen;
    }

    if (bufferLen + 8 > buffer.length) return null;
    buffer.writeInt32LE(-len, bufferLen);
    buffer.writeUInt32LE(ptr, bufferLen + 4);
    bufferLen += 8;
    index += len;
    lastEmitIndex = index;
  }

  // Emit everything left
  let copyLen = newText.length - lastEmitIndex;
  if (copyLen) {
    if (bufferLen + copyLen + 4 > buffer.length) return null;
    // Positive number encodes literal copy.
    buffer.writeInt32LE(copyLen, bufferLen);
    bufferLen += 4;
    newText.copy(buffer, bufferLen, lastEmitIndex, newText.length);
    bufferLen += copyLen;
  }

  return buffer.slice(0, bufferLen);
}

/**
 * Delta decode
 *
 * @param {Buffer} oldText Base of delta
 * @param {Buffer} delta Delta encoding
 * @param {Buffer} [buffer] Pre-allocated buffer to store the decoded result. If not supplied,
 *  a buffer of length `oldText.length + delta.length` will be allocated.
 * @return {Buffer} Delta decoded result. It will be `buffer` sliced to correct length. If the
 *  decoded result does not fit into `buffer`, `null` will be returned.
 */
function decode(oldText, delta, buffer) {
  if (!buffer) buffer = Buffer.alloc(oldText.length + delta.length);
  let bufferLen = 0;

  let index = 0;
  while (index <= delta.length - 4) {
    let len = delta.readInt32LE(index);
    index += 4;
    if (len >= 0) {
      // Copy literals
      if (index + len > delta.length) throw new RangeError('Malformed delta encoding');
      if (bufferLen + len > buffer.length) return null;
      delta.copy(buffer, bufferLen, index, index + len);
      bufferLen += len;
      index += len;
      continue;
    }

    if (index + 4 > delta.length) throw new RangeError('Malformed delta encoding');
    // Negative length encodes a delta range copy
    len = -len;
    let ptr = delta.readUInt32LE(index);
    index += 4;

    if (ptr + len > oldText.length) throw new RangeError('Malformed delta encoding');
    if (bufferLen + len > buffer.length) return null;
    oldText.copy(buffer, bufferLen, ptr, ptr + len);
    bufferLen += len;
  }

  if (index != delta.length) throw new RangeError('Malformed delta encoding');

  return buffer.slice(0, bufferLen);
}

exports.encode = encode;
exports.decode = decode;
