// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! ISO 9660 (ECMA-119), read-only, with Joliet and Rock Ridge.
//!
//! [`mount`] scans the volume descriptors from byte 32768 and picks the
//! tree to show: Rock Ridge when the root's `.` record carries an `SP`
//! entry, else Joliet when the disc has a supplementary descriptor for it,
//! else the plain ISO names. A folder is one contiguous extent of records;
//! a record never crosses a logical block, and a zero length byte pads to
//! the next block. A file is one or more extents (a run of records marked
//! "continues" is one file).
//!
//! Node ids are the volume byte offset of the directory record. The root's
//! is the record inside its volume descriptor.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::fs::{DirBatch, DirProgress, FileSystem};
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_iso9660::mount(source)?;
//! println!("{}", volume.info().name);
//!
//! let mut stream = volume.read_dir(volume.root())?;
//! let mut batch = DirBatch::new();
//! while stream.next_batch(&mut batch, 256)? == DirProgress::More {}
//! for entry in batch.iter() {
//!     println!("{}", entry.name);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::sync::Arc;

use atlas_fat::chain::{Chain, Run};
use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::fs::{
    DirBatch, DirEntry, DirProgress, DirStream, EntryFlags, Extent, FileSystem, Metadata, NodeId,
    NodeKind, Owner, Stream, Timestamp, VolumeInfo,
};
use atlas_fs_core::io::block::{BlockSource, MemSource};

// Seed inputs for the fuzz targets; `volumes()` is shared with Disk Atlas, which adds the probe heads.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod fuzz_seeds;
pub mod rr;
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(dead_code, missing_docs)]
pub mod test_image;

use rr::Rr;

/// The system area before the first volume descriptor.
const SYSTEM_AREA: u64 = 32768;
/// Bytes of a volume descriptor.
const DESCRIPTOR: u64 = 2048;
/// Most volume descriptors scanned.
const MAX_DESCRIPTORS: u64 = 64;
/// Largest folder read, in bytes.
pub const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;
/// Shortest directory record.
const MIN_RECORD: usize = 34;
/// Most extents one file may have.
const MAX_PARTS: usize = 1 << 16;
/// Bytes of folder read ahead when collecting a multi-extent file's parts.
const PART_SCAN: u64 = 1 << 20;
/// Where the root record sits inside a volume descriptor.
const ROOT_AT: u64 = 156;

const FLAG_HIDDEN: u8 = 0x01;
const FLAG_DIR: u8 = 0x02;
const FLAG_MORE: u8 = 0x80;

const STRUCTURE: &str = "ISO 9660 directory record";

/// Which names the volume shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tree {
    Plain,
    Joliet,
    RockRidge,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    let raw = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(raw.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let raw = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant). The caller
/// range-checks the inputs, so no step can overflow. Public for `atlas-udf`,
/// not part of the stable API.
#[doc(hidden)]
#[allow(clippy::arithmetic_side_effects)]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A civil date and time with an offset from UTC in quarter hours, as a
/// UTC [`Timestamp`]. `None` for a field out of range.
fn civil_timestamp(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    quarters: i64,
) -> Option<Timestamp> {
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day)
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second)
        .saturating_sub(quarters.saturating_mul(900));
    Some(Timestamp::from_unix(seconds, 0))
}

fn corrupt(location: Location, kind: CorruptKind) -> Error {
    Corruption::new(STRUCTURE, location, kind).into()
}

fn not_found(node: u64) -> Error {
    Error::NotFound { node }
}

/// A directory record, read.
#[derive(Debug, Clone)]
struct Rec {
    node: u64,
    /// Bytes the record takes in its folder.
    raw_len: usize,
    flags: u8,
    /// Byte offset of the content, past any extended attribute record.
    start: u64,
    len: u64,
    time: Option<Timestamp>,
    name: String,
    rr: Rr,
}

impl Rec {
    fn is_dir(&self) -> bool {
        self.flags & FLAG_DIR != 0 || self.rr.child_link.is_some()
    }

    /// The file continues in the next record.
    fn continues(&self) -> bool {
        self.flags & FLAG_MORE != 0 && !self.is_dir()
    }

    fn kind(&self) -> NodeKind {
        if self.is_dir() {
            return NodeKind::Directory;
        }
        if self.rr.symlink.is_some() {
            return NodeKind::Symlink;
        }
        match self.rr.mode.map(|m| m & 0o170_000) {
            Some(0o120_000) => NodeKind::Symlink,
            Some(0o010_000 | 0o020_000 | 0o060_000 | 0o140_000) => NodeKind::Other,
            _ => NodeKind::File,
        }
    }

    fn entry_flags(&self) -> EntryFlags {
        if self.flags & FLAG_HIDDEN != 0 {
            EntryFlags::HIDDEN
        } else {
            EntryFlags::EMPTY
        }
    }

    fn modified(&self) -> Option<Timestamp> {
        self.rr.modified.or(self.time)
    }
}

/// A file or folder as the listing shows it: the record, and every extent
/// after the first when the file has several.
#[derive(Debug)]
struct File {
    rec: Rec,
    size: u64,
    more: Vec<(u64, u64)>,
}

impl File {
    fn shown_size(&self) -> Option<u64> {
        match self.rec.kind() {
            NodeKind::Directory => None,
            NodeKind::Symlink => self
                .rec
                .rr
                .symlink
                .as_ref()
                .map(|t| u64::try_from(t.len()).unwrap_or(0)),
            _ => Some(self.size),
        }
    }
}

struct Inner {
    source: Arc<dyn BlockSource>,
    bs: u64,
    tree: Tree,
}

impl Inner {
    /// The Rock Ridge entries in `raw`'s system-use area, continuation
    /// areas included.
    fn system_use(&self, raw: &[u8]) -> Rr {
        let nl = usize::from(raw.get(32).copied().unwrap_or(0));
        let pad = usize::from(nl % 2 == 0);
        let begin = 33usize.saturating_add(nl).saturating_add(pad);
        let mut rr = Rr::default();
        let mut acc = rr::Acc::default();
        let mut next = rr::scan(raw.get(begin..).unwrap_or(&[]), &mut rr, &mut acc);
        let mut area = Vec::new();
        for _ in 0..rr::MAX_CE {
            let Some(ce) = next else { break };
            let len = u64::from(ce.len);
            if len == 0 || u64::from(ce.offset).saturating_add(len) > self.bs {
                break;
            }
            let Some(at) = u64::from(ce.block)
                .checked_mul(self.bs)
                .and_then(|b| b.checked_add(u64::from(ce.offset)))
            else {
                break;
            };
            let Ok(len) = usize::try_from(len) else { break };
            area.clear();
            area.resize(len, 0);
            if self.source.read_at(at, &mut area).is_err() {
                break;
            }
            next = rr::scan(&area, &mut rr, &mut acc);
        }
        acc.finish(&mut rr);
        rr
    }

    /// Reads the record `raw` found at `node`.
    fn parse(&self, raw: &[u8], node: u64) -> Result<Rec> {
        let here = Location::Byte(node);
        let invalid = |field: &'static str, value: usize| {
            corrupt(
                here,
                CorruptKind::InvalidValue {
                    field,
                    value: u64::try_from(value).unwrap_or(u64::MAX),
                },
            )
        };
        let nl = usize::from(
            raw.get(32)
                .copied()
                .ok_or_else(|| invalid("record length", 0))?,
        );
        let name_bytes = raw
            .get(33..33usize.saturating_add(nl))
            .ok_or_else(|| invalid("name length", nl))?;
        let (Some(&xar), Some(&flags), Some(extent), Some(len)) =
            (raw.get(1), raw.get(25), le32(raw, 2), le32(raw, 10))
        else {
            return Err(invalid("record length", raw.len()));
        };
        let start = u64::from(extent)
            .saturating_add(u64::from(xar))
            .checked_mul(self.bs)
            .ok_or_else(|| {
                corrupt(
                    here,
                    CorruptKind::Overflow {
                        field: "extent location",
                    },
                )
            })?;
        let rr = if self.tree == Tree::RockRidge {
            self.system_use(raw)
        } else {
            Rr::default()
        };
        let name = match (&rr.name, self.tree) {
            (Some(alt), Tree::RockRidge) => alt.clone(),
            (_, Tree::Joliet) => clean_name(&ucs2(name_bytes)),
            _ => clean_name(&latin(name_bytes)),
        };
        Ok(Rec {
            node,
            raw_len: raw.len(),
            flags,
            start,
            len: u64::from(len),
            time: raw.get(18..25).and_then(rr::short_time),
            name,
            rr,
        })
    }

    /// The record at `node`.
    fn read_rec(&self, node: u64) -> Result<Rec> {
        let size = self.source.len();
        if node < SYSTEM_AREA || node >= size {
            return Err(not_found(node));
        }
        let mut first = [0u8; 1];
        self.source.read_at(node, &mut first)?;
        let len = usize::from(first.first().copied().unwrap_or(0));
        if len < MIN_RECORD {
            return Err(not_found(node));
        }
        let wide = u64::try_from(len).unwrap_or(u64::MAX);
        let in_block = node.checked_rem(self.bs).unwrap_or(0);
        if in_block.saturating_add(wide) > self.bs || node.saturating_add(wide) > size {
            return Err(corrupt(
                Location::Byte(node),
                CorruptKind::InvalidValue {
                    field: "record length",
                    value: wide,
                },
            ));
        }
        let mut raw = vec![0u8; len];
        self.source.read_at(node, &mut raw)?;
        self.parse(&raw, node)
    }

    /// Where the content of folder `rec` lives: a Rock Ridge placeholder
    /// (`CL`) names the real folder's block, whose `.` record says how long
    /// it is.
    fn dir_extent(&self, rec: &Rec) -> Result<(u64, u64)> {
        if !rec.is_dir() {
            return Err(Error::NotADirectory { node: rec.node });
        }
        let Some(block) = rec.rr.child_link else {
            return Ok((rec.start, rec.len));
        };
        let start = u64::from(block).checked_mul(self.bs).ok_or_else(|| {
            corrupt(
                Location::Byte(rec.node),
                CorruptKind::Overflow {
                    field: "relocated folder",
                },
            )
        })?;
        let mut dot = [0u8; MIN_RECORD];
        if start.saturating_add(MIN_RECORD as u64) > self.source.len() {
            return Err(corrupt(
                Location::Byte(rec.node),
                CorruptKind::OutOfRange {
                    field: "relocated folder",
                    value: start,
                    limit_name: "volume size",
                    limit: self.source.len(),
                },
            ));
        }
        self.source.read_at(start, &mut dot)?;
        match (dot.first(), le32(&dot, 10)) {
            (Some(&l), Some(len)) if usize::from(l) >= MIN_RECORD => Ok((start, u64::from(len))),
            _ => Err(corrupt(
                Location::Byte(start),
                CorruptKind::InvalidValue {
                    field: "relocated folder's . record",
                    value: u64::from(dot.first().copied().unwrap_or(0)),
                },
            )),
        }
    }
}

/// ISO names are single-byte; Latin-1 covers whatever a mastering tool wrote.
fn latin(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

fn ucs2(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Drops the `;1` version and a trailing `.`, and keeps path separators and
/// NULs out of the name.
fn clean_name(raw: &str) -> String {
    let mut name = raw;
    if let Some((head, tail)) = name.rsplit_once(';')
        && !tail.is_empty()
        && tail.bytes().all(|b| b.is_ascii_digit())
    {
        name = head;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    name.replace(['/', '\0'], "_")
}

/// Walks the records of a run of directory bytes.
struct Walker {
    inner: Arc<Inner>,
    pos: u64,
    end: u64,
    block: Vec<u8>,
    block_at: u64,
}

impl Walker {
    /// The records of the folder at `start`, `len` bytes long (cut to
    /// [`MAX_DIR_BYTES`] and to the volume).
    fn folder(inner: Arc<Inner>, start: u64, len: u64) -> Result<Self> {
        let size = inner.source.len();
        let end = start.saturating_add(len.min(MAX_DIR_BYTES)).min(size);
        if len > 0 && start >= size {
            return Err(corrupt(
                Location::Byte(start),
                CorruptKind::OutOfRange {
                    field: "folder extent",
                    value: start,
                    limit_name: "volume size",
                    limit: size,
                },
            ));
        }
        Ok(Self::at(inner, start, end))
    }

    fn at(inner: Arc<Inner>, pos: u64, end: u64) -> Self {
        Self {
            inner,
            pos,
            end,
            block: Vec::new(),
            block_at: u64::MAX,
        }
    }

    fn load(&mut self, block_start: u64) -> Result<()> {
        let bs = usize::try_from(self.inner.bs).unwrap_or(0);
        let have = self
            .inner
            .source
            .len()
            .saturating_sub(block_start)
            .min(self.inner.bs);
        self.block.clear();
        self.block.resize(bs, 0);
        let have = usize::try_from(have).unwrap_or(0);
        if let Some(dst) = self.block.get_mut(..have) {
            self.inner.source.read_at(block_start, dst)?;
        }
        self.block_at = block_start;
        Ok(())
    }

    /// The next record that is not `.` or `..`. Every turn moves forward,
    /// so the walk ends at `end`.
    fn next_rec(&mut self) -> Result<Option<Rec>> {
        let bs = self.inner.bs;
        loop {
            if self.pos >= self.end {
                return Ok(None);
            }
            let in_block = self.pos.checked_rem(bs).unwrap_or(0);
            let block_start = self.pos.saturating_sub(in_block);
            if self.block_at != block_start {
                self.load(block_start)?;
            }
            let at = usize::try_from(in_block).unwrap_or(usize::MAX);
            let len = usize::from(self.block.get(at).copied().unwrap_or(0));
            if len == 0 {
                self.pos = block_start.saturating_add(bs);
                continue;
            }
            let Some(raw) = self
                .block
                .get(at..at.saturating_add(len))
                .filter(|_| len >= MIN_RECORD)
            else {
                return Err(corrupt(
                    Location::Byte(self.pos),
                    CorruptKind::InvalidValue {
                        field: "record length",
                        value: u64::try_from(len).unwrap_or(0),
                    },
                ));
            };
            let node = self.pos;
            self.pos = self.pos.saturating_add(u64::try_from(len).unwrap_or(0));
            if raw.get(32) == Some(&1) && matches!(raw.get(33), Some(0 | 1)) {
                continue;
            }
            return self.inner.parse(raw, node).map(Some);
        }
    }

    /// Reads the records that finish `first`, a file marked "continues".
    fn parts(&mut self, first: &Rec) -> Result<(u64, Vec<(u64, u64)>)> {
        let mut size = first.len;
        let mut more = Vec::new();
        let mut again = first.continues();
        while again {
            if more.len() >= MAX_PARTS {
                return Err(corrupt(
                    Location::Byte(first.node),
                    CorruptKind::LimitExceeded {
                        what: "extents of one file",
                        limit: MAX_PARTS as u64,
                    },
                ));
            }
            let Some(next) = self.next_rec()? else { break };
            size = size.saturating_add(next.len);
            more.push((next.start, next.len));
            again = next.continues();
        }
        Ok((size, more))
    }

    /// The next entry a listing shows (a relocated folder's real record is
    /// left out; its placeholder stands for it).
    fn next_file(&mut self) -> Result<Option<File>> {
        loop {
            let Some(rec) = self.next_rec()? else {
                return Ok(None);
            };
            if rec.rr.relocated {
                continue;
            }
            let (size, more) = self.parts(&rec)?;
            return Ok(Some(File { rec, size, more }));
        }
    }
}

/// A mounted ISO 9660 volume.
pub struct Iso {
    inner: Arc<Inner>,
    root: u64,
    info: VolumeInfo,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Iso>();
};

/// What the scan of the volume descriptors found.
struct Descriptors {
    primary: Vec<u8>,
    primary_at: u64,
    joliet: Option<(Vec<u8>, u64)>,
}

fn scan_descriptors(source: &dyn BlockSource) -> Result<Descriptors> {
    let mut primary = None;
    let mut joliet = None;
    let mut buf = vec![0u8; usize::try_from(DESCRIPTOR).unwrap_or(2048)];
    for i in 0..MAX_DESCRIPTORS {
        let at = SYSTEM_AREA.saturating_add(i.saturating_mul(DESCRIPTOR));
        if at.saturating_add(DESCRIPTOR) > source.len() {
            break;
        }
        source.read_at(at, &mut buf)?;
        if buf.get(1..6) != Some(b"CD001") {
            if i == 0 {
                return Err(Corruption::new(
                    "ISO 9660 volume descriptor",
                    Location::Byte(at),
                    CorruptKind::BadSignature {
                        expected: 0x0000_0043_4430_3031,
                        found: 0,
                    },
                )
                .into());
            }
            break;
        }
        match buf.first() {
            Some(1) if primary.is_none() => primary = Some((buf.clone(), at)),
            Some(2) if joliet.is_none() => {
                let escape = buf.get(88..91);
                if matches!(escape, Some(b"%/@" | b"%/C" | b"%/E")) {
                    joliet = Some((buf.clone(), at));
                }
            }
            Some(255) => break,
            _ => {}
        }
    }
    let Some((primary, primary_at)) = primary else {
        return Err(Corruption::new(
            "ISO 9660 volume descriptors",
            Location::Byte(SYSTEM_AREA),
            CorruptKind::Other("no primary volume descriptor"),
        )
        .into());
    };
    Ok(Descriptors {
        primary,
        primary_at,
        joliet,
    })
}

/// Mounts the ISO 9660 volume in `source`.
///
/// Fails when there is no primary volume descriptor or its block size or
/// root record is unusable.
pub fn mount(source: Arc<dyn BlockSource>) -> Result<Iso> {
    let found = scan_descriptors(&*source)?;
    let at = found.primary_at;
    let bs = le16(&found.primary, 128).map_or(0, u64::from);
    if !(512..=65536).contains(&bs) || !bs.is_power_of_two() {
        return Err(Corruption::new(
            "ISO 9660 primary volume descriptor",
            Location::Byte(at.saturating_add(128)),
            CorruptKind::InvalidValue {
                field: "logical block size",
                value: bs,
            },
        )
        .into());
    }
    let mut inner = Inner {
        source: Arc::clone(&source),
        bs,
        tree: Tree::Plain,
    };
    let root = at.saturating_add(ROOT_AT);
    let root_rec = inner.read_rec(root)?;
    if !root_rec.is_dir() {
        return Err(corrupt(
            Location::Byte(root),
            CorruptKind::InvalidValue {
                field: "root record flags",
                value: u64::from(root_rec.flags),
            },
        ));
    }
    // The tree: Rock Ridge announces itself in the root's `.` record.
    let mut tree = Tree::Plain;
    let mut root_at = root;
    let mut label_source = (&found.primary, false);
    if root_has_sp(&inner, &root_rec) {
        tree = Tree::RockRidge;
    } else if let Some((desc, jat)) = &found.joliet {
        tree = Tree::Joliet;
        root_at = jat.saturating_add(ROOT_AT);
        label_source = (desc, true);
    }
    inner.tree = tree;
    let label = if label_source.1 {
        ucs2(label_source.0.get(40..72).unwrap_or(&[]))
    } else {
        latin(label_source.0.get(40..72).unwrap_or(&[]))
    };
    let label = label.trim_end_matches([' ', '\0']).to_owned();
    let label = if label.is_empty() && label_source.1 {
        latin(found.primary.get(40..72).unwrap_or(&[]))
            .trim_end_matches([' ', '\0'])
            .to_owned()
    } else {
        label
    };
    let mut info = VolumeInfo::new(if label.is_empty() {
        "ISO 9660 volume".to_owned()
    } else {
        label
    });
    info.format = Some("ISO 9660");
    info.total_bytes = le32(&found.primary, 80)
        .map(|blocks| u64::from(blocks).saturating_mul(bs))
        .filter(|&b| b > 0);
    info.local_times = false;
    Ok(Iso {
        inner: Arc::new(inner),
        root: root_at,
        info,
    })
}

/// True when the first record of the root folder (`.`) holds an `SP` entry.
fn root_has_sp(inner: &Inner, root: &Rec) -> bool {
    let size = inner.source.len();
    if root.len == 0 || root.start.saturating_add(MIN_RECORD as u64) > size {
        return false;
    }
    let mut head = [0u8; 1];
    if inner.source.read_at(root.start, &mut head).is_err() {
        return false;
    }
    let len = usize::from(head.first().copied().unwrap_or(0));
    let wide = u64::try_from(len).unwrap_or(u64::MAX);
    if len < MIN_RECORD || wide > inner.bs || root.start.saturating_add(wide) > size {
        return false;
    }
    let mut raw = vec![0u8; len];
    if inner.source.read_at(root.start, &mut raw).is_err() {
        return false;
    }
    inner.system_use(&raw).has_sp
}

impl Iso {
    /// The entry at `node`, with all extents of a multi-extent file.
    fn file_at(&self, node: NodeId) -> Result<File> {
        let rec = self.inner.read_rec(node.0)?;
        if !rec.continues() {
            let size = rec.len;
            return Ok(File {
                rec,
                size,
                more: Vec::new(),
            });
        }
        let next = rec
            .node
            .saturating_add(u64::try_from(rec.raw_len).unwrap_or(0));
        let end = next.saturating_add(PART_SCAN).min(self.inner.source.len());
        let mut walker = Walker::at(Arc::clone(&self.inner), next, end);
        let (size, more) = walker.parts(&rec)?;
        Ok(File { rec, size, more })
    }

    fn folder_walker(&self, dir: NodeId) -> Result<Walker> {
        let rec = self.inner.read_rec(dir.0)?;
        let (start, len) = self.inner.dir_extent(&rec)?;
        Walker::folder(Arc::clone(&self.inner), start, len)
    }
}

struct IsoDir {
    walker: Walker,
    done: bool,
}

impl DirStream for IsoDir {
    fn next_batch(&mut self, out: &mut DirBatch, max: usize) -> Result<DirProgress> {
        if self.done {
            return Ok(DirProgress::Done);
        }
        let mut added = 0usize;
        while added < max {
            match self.walker.next_file() {
                Ok(Some(file)) => {
                    out.push(DirEntry {
                        node: NodeId(file.rec.node),
                        name: &file.rec.name,
                        kind: file.rec.kind(),
                        size: file.shown_size(),
                        resource_size: None,
                        modified: file.rec.modified(),
                        flags: file.rec.entry_flags(),
                    });
                    added = added.saturating_add(1);
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(DirProgress::Done);
                }
                Err(e) => {
                    self.done = true;
                    return Err(e);
                }
            }
        }
        Ok(DirProgress::More)
    }
}

impl FileSystem for Iso {
    fn info(&self) -> VolumeInfo {
        self.info.clone()
    }

    fn root(&self) -> NodeId {
        NodeId(self.root)
    }

    fn metadata(&self, node: NodeId) -> Result<Metadata> {
        let file = self.file_at(node)?;
        let rec = &file.rec;
        let owner = rec.rr.mode.map(|mode| Owner {
            user: rec.rr.uid,
            group: rec.rr.gid,
            mode: u16::try_from(mode & 0xFFFF).unwrap_or(0),
        });
        Ok(Metadata {
            node,
            kind: rec.kind(),
            size: file.shown_size(),
            resource_size: None,
            created: rec.rr.created,
            modified: rec.modified(),
            accessed: rec.rr.accessed,
            flags: rec.entry_flags(),
            link_target: rec.rr.symlink.clone(),
            finder_codes: None,
            owner,
            attributes: None,
            finder_info: None,
        })
    }

    fn lookup(&self, dir: NodeId, name: &str) -> Result<Option<NodeId>> {
        let exact = self.inner.tree == Tree::RockRidge;
        let want: String = if exact {
            name.to_owned()
        } else {
            name.chars().flat_map(char::to_lowercase).collect()
        };
        let mut walker = self.folder_walker(dir)?;
        while let Some(file) = walker.next_file()? {
            let hit = if exact {
                file.rec.name == want
            } else {
                file.rec
                    .name
                    .chars()
                    .flat_map(char::to_lowercase)
                    .eq(want.chars())
            };
            if hit {
                return Ok(Some(NodeId(file.rec.node)));
            }
        }
        Ok(None)
    }

    fn read_dir(&self, dir: NodeId) -> Result<Box<dyn DirStream>> {
        Ok(Box::new(IsoDir {
            walker: self.folder_walker(dir)?,
            done: false,
        }))
    }

    fn extents(&self, node: NodeId, stream: Stream) -> Result<Vec<Extent>> {
        let file = self.file_at(node)?;
        if file.rec.is_dir() {
            return Err(Error::IsADirectory { node: node.0 });
        }
        if stream == Stream::Resource || file.rec.kind() == NodeKind::Symlink {
            return Ok(Vec::new());
        }
        let size = self.inner.source.len();
        let mut out: Vec<Extent> = Vec::new();
        let parts =
            std::iter::once((file.rec.start, file.rec.len)).chain(file.more.iter().copied());
        for (start, len) in parts {
            if len == 0 {
                continue;
            }
            if start >= size {
                return Err(corrupt(
                    Location::Byte(node.0),
                    CorruptKind::OutOfRange {
                        field: "file extent",
                        value: start,
                        limit_name: "volume size",
                        limit: size,
                    },
                ));
            }
            let len = len.min(size.saturating_sub(start));
            match out.last_mut() {
                Some(last) if last.offset.saturating_add(last.len) == start => {
                    last.len = last.len.saturating_add(len);
                }
                _ => out.push(Extent { offset: start, len }),
            }
        }
        Ok(out)
    }

    fn open(&self, node: NodeId, stream: Stream) -> Result<Arc<dyn BlockSource>> {
        let file = self.file_at(node)?;
        if file.rec.is_dir() {
            return Err(Error::IsADirectory { node: node.0 });
        }
        if stream == Stream::Resource {
            return Err(Error::NoSuchStream { node: node.0 });
        }
        if let Some(target) = &file.rec.rr.symlink {
            return Ok(Arc::new(MemSource::new(target.clone().into_bytes())));
        }
        let mut runs = Vec::new();
        let mut at = 0u64;
        let parts =
            std::iter::once((file.rec.start, file.rec.len)).chain(file.more.iter().copied());
        for (start, len) in parts {
            if len == 0 {
                continue;
            }
            if start.checked_add(len).is_none() {
                return Err(corrupt(
                    Location::Byte(node.0),
                    CorruptKind::Overflow {
                        field: "file extent",
                    },
                ));
            }
            runs.push(Run {
                file_start: at,
                disk: start,
                len,
            });
            at = at.saturating_add(len);
        }
        if runs.is_empty() {
            return Ok(Arc::new(Chain::empty(Arc::clone(&self.inner.source))));
        }
        Ok(Arc::new(Chain::from_runs(
            Arc::clone(&self.inner.source),
            runs,
            None,
        )))
    }
}

#[cfg(test)]
mod tests;
