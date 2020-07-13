use super::*;

#[test]
fn open_archive() {
    WillArchive::from_bytes(include_bytes!("../test/NUKITASHI_T.WAR")).unwrap();
}
