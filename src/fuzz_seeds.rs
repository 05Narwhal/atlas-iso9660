// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Seed inputs for the ISO 9660 fuzz target in `fuzz/`.

use super::test_image::{Entry, Opts, build};

fn tree() -> Vec<Entry> {
    vec![
        Entry::file("readme.txt", b"hello disc"),
        Entry::dir("Docs", vec![Entry::file("Report.txt", &[7u8; 3000])]),
        Entry::multi("big.bin", &[&[1u8; 2048], &[2u8; 100]]),
        Entry::link("current", "../lib/x"),
    ]
}

/// A plain, a Rock Ridge and a Joliet image of the same tree.
pub fn volumes() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("iso-plain", build(&tree(), &Opts::default())),
        (
            "iso-rockridge",
            build(
                &tree(),
                &Opts {
                    rock_ridge: true,
                    joliet: false,
                },
            ),
        ),
        (
            "iso-joliet",
            build(
                &tree(),
                &Opts {
                    rock_ridge: false,
                    joliet: true,
                },
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use atlas_fs_core::fs::FileSystem;
    use atlas_fs_core::io::block::MemSource;

    use super::volumes;

    /// The largest input the fuzz run accepts (`-max_len=1048576`).
    const MAX_SEED: usize = 1 << 20;

    /// Writes the seeds into `$ATLAS_FUZZ_SEEDS/iso9660_mount`, with an `iso-`
    /// prefix so other seeds in that folder stay. Run it with
    /// `cargo test --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes files; run by the fuzz CI job"]
    fn write_fuzz_seeds() {
        let Some(root) = std::env::var_os("ATLAS_FUZZ_SEEDS") else {
            return;
        };
        let mount_dir = Path::new(&root).join("iso9660_mount");
        fs::create_dir_all(&mount_dir).expect("create seed directory");
        for (name, image) in volumes() {
            fs::write(mount_dir.join(name), &image).expect("write mount seed");
        }
    }

    /// Every seed fits the run's input limit, mounts and lists its root.
    #[test]
    fn mount_seeds_are_valid_and_small() {
        for (name, image) in volumes() {
            assert!(image.len() <= MAX_SEED, "{name}: {} bytes", image.len());
            let volume = crate::mount(Arc::new(MemSource::new(image)))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(volume.read_dir(volume.root()).is_ok(), "{name}");
        }
    }
}
