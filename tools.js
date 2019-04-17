
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
        while ([k, v] = await next()) {
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
