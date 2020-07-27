//! Binary delta encoding/decoding algorithm.
//!
//! References:
//! https://www.fossil-scm.org/index.html/doc/trunk/www/delta_encoder_algorithm.wiki
//! https://en.wikipedia.org/wiki/Rolling_hash

use byteorder::{ByteOrder, LE};
use fnv::FnvHashMap;

const HASH_LENGTH: usize = 16;

const HASH_ROLL_MAGIC: u64 = {
    let mut result = 1u64;
    let mut i = 0;
    // Use while instead of loop to allow const.
    while i < HASH_LENGTH {
        result = result.wrapping_mul(31);
        i += 1;
    }
    result
};

/// Cyclic polynomial hashing function, hash `HASH_LENGTH` bytes.
fn calc_hash(buffer: &[u8]) -> u64 {
    let mut hash = 0u64;
    for i in 0..HASH_LENGTH {
        hash = hash.wrapping_mul(31).wrapping_add(buffer[i] as u64);
    }
    hash
}

/// Rolls the hash one byte to the next. `hash` should be identical to `calc_hash(buffer)`.
/// `calc_hash(&buffer[1..])` will be returned.
fn roll_hash(buffer: &[u8], hash: u64) -> u64 {
    hash.wrapping_mul(31)
        .wrapping_sub(HASH_ROLL_MAGIC.wrapping_mul(buffer[0] as u64))
        .wrapping_add(buffer[HASH_LENGTH] as u64)
}

/// Perform delta encoding.
pub fn calc_delta(base: &[u8], new: &[u8], buffer: &mut Vec<u8>) {
    // Build hash table for `base` for speed up
    let mut hashmap = FnvHashMap::default();
    // Calculate from back to front to prioritise blocks in the beginning, as
    // * it is searched first, and
    // * in repetitive cases, it can capture longer duplication
    for i in (0..base.len() - HASH_LENGTH + 1).step_by(HASH_LENGTH).rev() {
        let hash = calc_hash(&base[i..]);
        hashmap.insert(hash, i);
    }

    // Last emit index tracks the earliest possible location that we can go back.
    let mut last_emit_index = 0;
    let mut index = 0;

    // Set index to a number so first iteration always recalculate it.
    let mut hash_index = 0;
    let mut hash = 0;

    while index <= new.len() - HASH_LENGTH {
        // Recalculate or rolls the hash based on index
        hash = if hash_index + 1 == index {
            roll_hash(&new[(index - 1)..], hash)
        } else {
            calc_hash(&new[index..])
        };
        hash_index = index;

        // If no match, skip
        let mut ptr = match hashmap.get(&hash) {
            Some(v) => *v,
            None => {
                index += 1;
                continue;
            }
        };

        // Skip if there is a collision.
        if base[ptr..(ptr + HASH_LENGTH)] != new[index..(index + HASH_LENGTH)] {
            index += 1;
            continue;
        }

        // First backtrack to see if we can find extra matches, but we cannot go beyond last_emit_index
        let mut len = HASH_LENGTH;
        while index > last_emit_index && ptr > 0 && base[ptr - 1] == new[index - 1] {
            ptr -= 1;
            index -= 1;
            len += 1;
        }

        // Search forward to match as long as possible.
        let len_max = (base.len() - ptr).min(new.len() - index);
        while len < len_max && base[ptr + len] == new[index + len] {
            len += 1
        }

        // Emit all literals as is.
        let copy_len = index - last_emit_index;
        if copy_len != 0 {
            // Positive number encodes literal copy.
            buffer.extend_from_slice(&(copy_len as u32).to_le_bytes());
            buffer.extend_from_slice(&new[last_emit_index..index]);
        }

        buffer.extend_from_slice(&(-(len as i32)).to_le_bytes());
        buffer.extend_from_slice(&(ptr as u32).to_le_bytes());
        index += len;
        last_emit_index = index;
    }

    // Emit everything left
    let copy_len = new.len() - last_emit_index;
    if copy_len != 0 {
        // Positive number encodes literal copy.
        buffer.extend_from_slice(&(copy_len as u32).to_le_bytes());
        buffer.extend_from_slice(&new[last_emit_index..]);
    }
}

/// Error indicating an invalid delta.
#[derive(Debug)]
pub struct InvalidDeltaError;

/// Decode delta-encoded data against base.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<(), InvalidDeltaError> {
    buffer.clear();
    let mut delta = delta;
    while !delta.is_empty() {
        if delta.len() < 4 {
            return Err(InvalidDeltaError);
        }
        let len = LE::read_u32(delta) as i32;
        delta = &delta[4..];

        if len >= 0 {
            let len = len as usize;
            if delta.len() < len {
                return Err(InvalidDeltaError);
            }
            buffer.extend_from_slice(&delta[..len]);
            delta = &delta[len..];
            continue;
        }

        let len = (-len) as usize;
        if delta.len() < 4 {
            return Err(InvalidDeltaError);
        }
        let ptr = LE::read_u32(delta) as usize;
        delta = &delta[4..];

        if ptr + len > base.len() {
            return Err(InvalidDeltaError);
        }
        buffer.extend_from_slice(&base[ptr..(ptr + len)]);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let old: &[u8] = b"This is the old opening. This is the old ending";
        let new: &[u8] =
            b"This is the old opening. This is the new paragraph. This is the old ending.";
        let mut delta = Vec::new();
        calc_delta(&old, &new, &mut delta);
        let mut reconstruct = Vec::new();
        apply_delta(&old, &delta, &mut reconstruct).unwrap();

        // Make sure this is indeed a compression
        assert!(delta.len() < new.len());
        // Make sure decompression matches compression
        assert_eq!(new, &reconstruct[..]);
    }
}
