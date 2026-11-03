use hydradragonclamav::{Engine, ScanOptions};

/// The second load reads the atom filter from `<dir>.atomfilter.cache` and
/// must detect exactly what a freshly built filter detects; a changed
/// signature file must not reuse the old cache.
#[test]
fn cached_atom_filter_matches_a_fresh_build() {
    let root = std::env::temp_dir().join(format!("hdav_afc_{}", std::process::id()));
    let db = root.join("db");
    std::fs::create_dir_all(&db).unwrap();
    std::fs::write(
        db.join("t.ndb"),
        "Test.Cache.A:0:*:4879647261447261676f6e5465737441746f6d\nTest.Cache.B:0:*:4142434445464748494a\n",
    )
    .unwrap();
    std::fs::write(db.join("t.ldb"), "Test.Cache.L;Target:0;0&1;6869646472613d;647261676f6e21\n").unwrap();
    let cache = root.join("db.atomfilter.cache");

    let sample = b"zz HydraDragonTestAtom ABCDEFGHIJ hiddra= dragon! zz".to_vec();
    let names = |e: &Engine| {
        let mut n: Vec<String> = e.scan_bytes(&sample, ScanOptions::default()).into_iter().map(|m| m.name).collect();
        n.sort();
        n
    };

    let (fresh, _) = Engine::from_database_dir(&db).unwrap();
    assert!(cache.is_file(), "first load writes the cache");
    let expected = names(&fresh);
    assert_eq!(expected.len(), 3, "{expected:?}");

    let (cached, _) = Engine::from_database_dir(&db).unwrap();
    assert_eq!(names(&cached), expected);

    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(db.join("t.ndb"), "Test.Cache.A:0:*:4879647261447261676f6e5465737441746f6d\n").unwrap();
    let (changed, _) = Engine::from_database_dir(&db).unwrap();
    assert_eq!(names(&changed), vec!["Test.Cache.A".to_string(), "Test.Cache.L".to_string()]);

    let _ = std::fs::remove_dir_all(&root);
}
