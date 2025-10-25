use std::{env, path::PathBuf};

use tauri_build::is_dev;

fn main() {
    let library_dir: PathBuf = [&env::var("CARGO_MANIFEST_DIR").unwrap(), "lib"]
        .iter()
        .collect();
    println!(
        "cargo:rustc-link-search=native={}",
        library_dir.to_string_lossy()
    );

    if is_dev() {
        tauri_build::build();
    } else {
        let windows = tauri_build::WindowsAttributes::new();

        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
            .expect("failed to run build script");
    }
}
