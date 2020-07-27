use delta_db::{Database, Options, Compression};

#[test]
fn test_lorem() {
    let dir = tempfile::Builder::new()
        .prefix("deltadb-test")
        .tempdir()
        .unwrap();
    let mut opts = Options::new();
    opts.set_verify_on_retrieval(true);
    opts.set_compression(Compression::Zlib);
    let db = Database::open(&dir, &opts).unwrap();
    let mut hashs = vec![db.insert("".into()).unwrap()];
    for i in 1..2000 {
        let str = lipsum::lipsum_words_from_seed(i, 0);
        let new_hash = db.insert(str.into()).unwrap();
        db.link(hashs.last().unwrap(), &new_hash).unwrap();
        hashs.push(new_hash);
        println!("\x1b[1A\r\x1b[0KProcessed {} entries", i);
    }
    println!();

    for (i, hash) in hashs.iter().enumerate() {
        assert_eq!(lipsum::lipsum_words_from_seed(i, 0).as_bytes(), &db.get(hash).unwrap().unwrap()[..]);
        println!("\x1b[1A\r\x1b[0KChecked {} entries", i);
    }
    println!();

    for (i, hash) in hashs.iter().enumerate() {
        db.get(hash).unwrap().unwrap();
        println!("\x1b[1A\r\x1b[0KChecked {} entries", i);
    }
    println!();
}
