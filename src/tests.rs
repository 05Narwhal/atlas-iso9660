// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

use super::test_image::{BLOCK, CE_NAME_LEN, Entry, Opts, TF_SECONDS, UNIX_SECONDS, build};
use super::*;
use atlas_fat::test_volume::pattern;
use atlas_fs_core::fs::DirBatch;

fn mounted(image: Vec<u8>) -> Iso {
    mount(Arc::new(MemSource::new(image))).expect("mount")
}

fn list(fs: &Iso, dir: NodeId) -> Vec<(String, NodeId, NodeKind, Option<u64>)> {
    let mut stream = fs.read_dir(dir).unwrap();
    let mut batch = DirBatch::default();
    let mut out = Vec::new();
    loop {
        batch.clear();
        let progress = stream.next_batch(&mut batch, 2).unwrap();
        out.extend(
            batch
                .iter()
                .map(|e| (e.name.to_owned(), e.node, e.kind, e.size)),
        );
        if progress == DirProgress::Done {
            return out;
        }
    }
}

fn read_all(source: &dyn BlockSource) -> Vec<u8> {
    let mut buf = vec![0u8; usize::try_from(source.len()).unwrap()];
    source.read_at(0, &mut buf).unwrap();
    buf
}

fn tree() -> Vec<Entry> {
    vec![
        Entry::file("readme.txt", b"hello disc"),
        Entry::file("noext", &pattern(5000, 3)),
        Entry::dir(
            "Docs",
            vec![
                Entry::file("Report 2020.txt", &pattern(2048, 9)),
                Entry::file("empty.bin", b""),
                Entry::dir("deep", vec![Entry::file("leaf.dat", &pattern(3000, 1))]),
            ],
        ),
        Entry::multi(
            "big.bin",
            &[&pattern(2048, 4), &pattern(100, 5), &pattern(2049, 6)],
        ),
        Entry::file("secret.txt", b"shh").hidden(),
    ]
}

#[test]
fn plain_tree_lists_and_reads() {
    let fs = mounted(build(&tree(), &Opts::default()));
    assert_eq!(fs.info().format, Some("ISO 9660"));
    assert_eq!(fs.info().name, "ATLAS");
    assert!(!fs.info().local_times);
    let root = list(&fs, fs.root());
    let names: Vec<_> = root.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        names,
        ["README.TXT", "NOEXT", "DOCS", "BIG.BIN", "SECRET.TXT"]
    );
    let noext = fs.lookup(fs.root(), "noext").unwrap().unwrap();
    assert_eq!(
        read_all(&*fs.open(noext, Stream::Data).unwrap()),
        pattern(5000, 3)
    );
    let meta = fs.metadata(noext).unwrap();
    assert_eq!(meta.size, Some(5000));
    assert_eq!(meta.modified.unwrap().unix_seconds(), UNIX_SECONDS);
    let docs = fs.lookup(fs.root(), "docs").unwrap().unwrap();
    assert_eq!(fs.metadata(docs).unwrap().kind, NodeKind::Directory);
    let kids = list(&fs, docs);
    assert_eq!(kids.len(), 3);
    let deep = fs.lookup(docs, "DEEP").unwrap().unwrap();
    let leaf = fs.lookup(deep, "leaf.dat").unwrap().unwrap();
    assert_eq!(
        read_all(&*fs.open(leaf, Stream::Data).unwrap()),
        pattern(3000, 1)
    );
    let empty = fs.lookup(docs, "empty.bin").unwrap().unwrap();
    assert_eq!(fs.open(empty, Stream::Data).unwrap().len(), 0);
    assert!(fs.extents(empty, Stream::Data).unwrap().is_empty());
    assert!(fs.lookup(docs, "missing").unwrap().is_none());
    assert!(matches!(
        fs.open(docs, Stream::Data),
        Err(Error::IsADirectory { .. })
    ));
    assert!(matches!(
        fs.read_dir(noext),
        Err(Error::NotADirectory { .. })
    ));
    assert!(matches!(
        fs.open(noext, Stream::Resource),
        Err(Error::NoSuchStream { .. })
    ));
}

#[test]
fn hidden_flag_and_multi_extent_file() {
    let fs = mounted(build(&tree(), &Opts::default()));
    let mut batch = DirBatch::default();
    let mut stream = fs.read_dir(fs.root()).unwrap();
    stream.next_batch(&mut batch, 100).unwrap();
    let hidden: Vec<_> = batch
        .iter()
        .filter(|e| e.flags.contains(EntryFlags::HIDDEN))
        .map(|e| e.name.to_owned())
        .collect();
    assert_eq!(hidden, ["SECRET.TXT"]);
    let big = fs.lookup(fs.root(), "big.bin").unwrap().unwrap();
    let want: Vec<u8> = [pattern(2048, 4), pattern(100, 5), pattern(2049, 6)].concat();
    assert_eq!(fs.metadata(big).unwrap().size, Some(want.len() as u64));
    assert_eq!(read_all(&*fs.open(big, Stream::Data).unwrap()), want);
    let extents = fs.extents(big, Stream::Data).unwrap();
    assert_eq!(
        extents.iter().map(|e| e.len).sum::<u64>(),
        want.len() as u64
    );
    // The three parts are one file in the listing.
    assert_eq!(
        list(&fs, fs.root())
            .iter()
            .filter(|e| e.0 == "BIG.BIN")
            .count(),
        1
    );
}

#[test]
fn rock_ridge_names_modes_links_and_long_names() {
    let long = "L".repeat(CE_NAME_LEN + 30);
    let entries = vec![
        Entry::file("Mixed Case.txt", b"data"),
        Entry::file(&long, b"long"),
        Entry::link("current", "/usr/../lib/./x"),
        Entry::dir("sub", vec![Entry::file("a", b"a")]),
    ];
    let fs = mounted(build(
        &entries,
        &Opts {
            rock_ridge: true,
            joliet: true,
        },
    ));
    let names: Vec<_> = list(&fs, fs.root()).into_iter().map(|e| e.0).collect();
    assert_eq!(names, ["Mixed Case.txt", long.as_str(), "current", "sub"]);
    // Rock Ridge names are case sensitive.
    assert!(fs.lookup(fs.root(), "mixed case.txt").unwrap().is_none());
    let node = fs.lookup(fs.root(), "Mixed Case.txt").unwrap().unwrap();
    let meta = fs.metadata(node).unwrap();
    assert_eq!(meta.modified.unwrap().unix_seconds(), TF_SECONDS);
    let owner = meta.owner.unwrap();
    assert_eq!(
        (owner.user, owner.group, owner.mode),
        (1000, 100, 0o100_644)
    );
    let link = fs.lookup(fs.root(), "current").unwrap().unwrap();
    let meta = fs.metadata(link).unwrap();
    assert_eq!(meta.kind, NodeKind::Symlink);
    assert_eq!(meta.link_target.as_deref(), Some("/usr/../lib/./x"));
    assert_eq!(
        read_all(&*fs.open(link, Stream::Data).unwrap()),
        b"/usr/../lib/./x"
    );
    let sub = fs.lookup(fs.root(), "sub").unwrap().unwrap();
    assert_eq!(fs.metadata(sub).unwrap().owner.unwrap().mode, 0o040_755);
    assert_eq!(list(&fs, sub).len(), 1);
}

#[test]
fn joliet_names_win_without_rock_ridge() {
    let entries = vec![
        Entry::file("Ünïcode name.txt", b"j"),
        Entry::dir("Ordner", vec![]),
    ];
    let fs = mounted(build(
        &entries,
        &Opts {
            rock_ridge: false,
            joliet: true,
        },
    ));
    assert_eq!(fs.info().name, "Atlas Ünï");
    let names: Vec<_> = list(&fs, fs.root()).into_iter().map(|e| e.0).collect();
    assert_eq!(names, ["Ünïcode name.txt", "Ordner"]);
    assert!(fs.lookup(fs.root(), "ünïcode NAME.txt").unwrap().is_some());
}

#[test]
fn rock_ridge_entries_scan() {
    // CL, RE, a short TF and a continuation, then ST: nothing after ST counts.
    let mut area = vec![b'C', b'L', 12, 1];
    area.extend_from_slice(&5u32.to_le_bytes());
    area.extend_from_slice(&5u32.to_be_bytes());
    area.extend_from_slice(&[b'R', b'E', 4, 1]);
    area.extend_from_slice(&[b'C', b'E', 28, 1]);
    for v in [7u32, 8, 9] {
        area.extend_from_slice(&v.to_le_bytes());
        area.extend_from_slice(&v.to_be_bytes());
    }
    area.extend_from_slice(&[b'S', b'T', 4, 1, b'R', b'E', 4, 1]);
    let mut rr = Rr::default();
    let mut acc = rr::Acc::default();
    let ce = rr::scan(&area, &mut rr, &mut acc).unwrap();
    assert_eq!(rr.child_link, Some(5));
    assert!(rr.relocated);
    assert_eq!((ce.block, ce.offset, ce.len), (7, 8, 9));
    // Damaged lengths end the scan instead of reading past the area.
    for bad in [
        &[b'N', b'M', 200, 1, 0, b'x'][..],
        &[b'P', b'X', 3, 1][..],
        &[b'T', b'F', 12, 1, 0xFF, 1][..],
    ] {
        let mut rr = Rr::default();
        let mut acc = rr::Acc::default();
        assert!(rr::scan(bad, &mut rr, &mut acc).is_none());
        assert!(rr.mode.is_none() && rr.created.is_none());
    }
}

#[test]
fn damaged_volumes_fail_or_list_without_panicking() {
    let image = build(
        &tree(),
        &Opts {
            rock_ridge: true,
            joliet: true,
        },
    );
    // No descriptors, a bad block size, a truncated disc.
    assert!(mount(Arc::new(MemSource::new(vec![0u8; 40_000]))).is_err());
    let mut bad = image.clone();
    bad[16 * BLOCK + 128..16 * BLOCK + 130].copy_from_slice(&[3, 0]);
    assert!(mount(Arc::new(MemSource::new(bad))).is_err());
    for cut in [
        16 * BLOCK + 100,
        18 * BLOCK,
        19 * BLOCK + 50,
        image.len() / 2,
    ] {
        if let Ok(fs) = mount(Arc::new(MemSource::new(image[..cut].to_vec()))) {
            exercise(&fs);
        }
    }
    // A folder that lists itself: the walk stays finite and the entry's node
    // is the same each time, so a scan with a visited set stops.
    let plain = build(&tree(), &Opts::default());
    let fs = mounted(plain.clone());
    let docs = fs.lookup(fs.root(), "docs").unwrap().unwrap();
    let rec_at = docs.0 as usize;
    let mut looped = plain;
    let root_ext = u32::from_le_bytes(
        looped[16 * BLOCK + 158..16 * BLOCK + 162]
            .try_into()
            .unwrap(),
    );
    looped[rec_at + 2..rec_at + 6].copy_from_slice(&root_ext.to_le_bytes());
    looped[rec_at + 6..rec_at + 10].copy_from_slice(&root_ext.to_be_bytes());
    let fs = mounted(looped);
    let docs = fs.lookup(fs.root(), "docs").unwrap().unwrap();
    assert_eq!(list(&fs, docs).iter().filter(|e| e.0 == "DOCS").count(), 1);
    assert_eq!(
        list(&fs, docs).iter().find(|e| e.0 == "DOCS").unwrap().1,
        docs
    );
}

/// Lists, looks up, describes and reads within bounds; errors are fine.
fn exercise(fs: &Iso) {
    let mut todo = vec![(fs.root(), 0usize)];
    let mut budget = 500;
    while let Some((dir, depth)) = todo.pop() {
        let Ok(mut stream) = fs.read_dir(dir) else {
            continue;
        };
        let mut batch = DirBatch::default();
        loop {
            batch.clear();
            let Ok(progress) = stream.next_batch(&mut batch, 16) else {
                break;
            };
            for e in batch.iter() {
                budget -= 1;
                if budget == 0 {
                    return;
                }
                let _ = fs.metadata(e.node);
                let _ = fs.extents(e.node, Stream::Data);
                let _ = fs.lookup(dir, e.name);
                if e.kind == NodeKind::Directory && depth < 4 {
                    todo.push((e.node, depth + 1));
                } else if let Ok(src) = fs.open(e.node, Stream::Data) {
                    let mut buf = vec![0u8; usize::try_from(src.len().min(8192)).unwrap()];
                    let _ = src.read_at(0, &mut buf);
                }
            }
            if progress == DirProgress::Done {
                break;
            }
        }
    }
}

#[test]
fn every_flipped_byte_in_the_metadata_is_survived() {
    let image = build(
        &tree(),
        &Opts {
            rock_ridge: true,
            joliet: true,
        },
    );
    // Descriptors and folders are the first blocks after the system area.
    let end = 16 * BLOCK + 12 * BLOCK;
    for at in (16 * BLOCK..end).step_by(3) {
        for xor in [0xFFu8, 0x80, 0x01] {
            let mut bad = image.clone();
            bad[at] ^= xor;
            if let Ok(fs) = mount(Arc::new(MemSource::new(bad))) {
                exercise(&fs);
            }
        }
    }
}
