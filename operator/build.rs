use std::{fs::read_dir, path::Path};

fn main() {
    watch_directory(&"resources");
}

fn watch_directory<PATH: AsRef<Path>>(path: &PATH) {
    let path = path.as_ref();
    if path.is_dir() {
        for entry in read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                watch_directory(&path);
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
