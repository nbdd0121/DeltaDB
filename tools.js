const { promisify } = require('util');

/**
 * Copy one BlobDatabase into another one. Databases can have different compression settings.
 *
 * @param {BlobDatabase} oldDb
 * @param {BlobDatabase} newDb
 */
async function copy(oldDb, newDb) {
    let iter = oldDb._db.iterator();
    let next = () => new Promise((resolve, reject) => iter.next((err, key, value) => {
        if (err) return reject(err);
        else resolve([key, value]);
    }));
    console.log();
    let bytes = 0;
    try {
        let k, v;
        while ([k, v] = await next(), k) {
            let blob = await oldDb._rawToBlob(k, v);
            await newDb._blobPut(blob);
            bytes += v.length;
            console.log(`\x1b[1A\r\x1b[0KProcessed ${bytes} bytes`);
        }
    } finally {
        await promisify(cb => iter.end(cb))();
    }
}
exports.copy = copy;

/**
 * Call `get()` on all blobs.  If db is opened with `{ verify: true }`, this can be used to detect
 * potential corruptions.
 *
 * @param {BlobDatabase} db
 */
async function validate(db) {
    let iter = db._db.iterator();
    let next = () => new Promise((resolve, reject) => iter.next((err, key) => {
        if (err) return reject(err);
        else resolve(key);
    }));
    console.log();
    let entries = 0;
    try {
        let k;
        while (k = await next()) {
            await db.get(k);
            entries++;
            console.log(`\x1b[1A\r\x1b[0KProcessed ${entries} entries`);
        }
    } finally {
        await promisify(cb => iter.end(cb))();
    }
}
exports.validate = validate;
