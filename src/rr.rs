// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Rock Ridge (RRIP) entries in a directory record's system-use area.
//!
//! The scan is forgiving: an entry that is too short or too long for its
//! area ends the area, and a field that cannot be read is left unset. The
//! record's plain ISO name is what remains when Rock Ridge says nothing.

use super::{Timestamp, civil_timestamp, le32};

/// Most continuation areas (`CE`) followed for one record.
pub const MAX_CE: usize = 8;
/// Longest Rock Ridge name kept, in bytes.
const MAX_NAME: usize = 1024;
/// Longest symbolic link target kept, in bytes.
const MAX_LINK: usize = 4096;

/// What a record's Rock Ridge entries say.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Rr {
    /// The area holds an `SP` indicator (only meaningful in the root's `.`).
    pub has_sp: bool,
    /// The alternate name (`NM`).
    pub name: Option<String>,
    /// POSIX mode (`PX`).
    pub mode: Option<u32>,
    /// Owner user (`PX`).
    pub uid: u32,
    /// Owner group (`PX`).
    pub gid: u32,
    /// Symbolic link target (`SL`).
    pub symlink: Option<String>,
    /// The record is a relocated folder's real entry (`RE`): hidden, the
    /// placeholder (`CL`) shows it where it belongs.
    pub relocated: bool,
    /// The record is a placeholder for the folder at this block (`CL`).
    pub child_link: Option<u32>,
    /// Creation time (`TF`).
    pub created: Option<Timestamp>,
    /// Modification time (`TF`).
    pub modified: Option<Timestamp>,
    /// Access time (`TF`).
    pub accessed: Option<Timestamp>,
}

/// Where a continuation area is (`CE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation {
    /// Logical block of the area.
    pub block: u32,
    /// Byte offset inside that block.
    pub offset: u32,
    /// Length of the area in bytes.
    pub len: u32,
}

/// Pieces that span entries and areas.
#[derive(Debug, Default)]
pub struct Acc {
    name: Vec<u8>,
    link: Vec<u8>,
    link_seen: bool,
    link_sep: bool,
    link_open: bool,
}

impl Acc {
    /// Moves the assembled name and link into `rr`.
    pub fn finish(self, rr: &mut Rr) {
        if !self.name.is_empty() {
            let text = String::from_utf8_lossy(&self.name).replace(['/', '\0'], "_");
            if text != "." && text != ".." {
                rr.name = Some(text);
            }
        }
        if self.link_seen {
            rr.symlink = Some(String::from_utf8_lossy(&self.link).into_owned());
        }
    }
}

/// Reads the entries of one system-use `area` into `rr` and `acc`. Returns
/// the continuation area the entries point to, if any.
pub fn scan(area: &[u8], rr: &mut Rr, acc: &mut Acc) -> Option<Continuation> {
    let mut at = 0usize;
    let mut next = None;
    while let Some(head) = area.get(at..at.saturating_add(4)) {
        let (Some(&len), Some(&a), Some(&b)) = (head.get(2), head.first(), head.get(1)) else {
            break;
        };
        let len = usize::from(len);
        let Some(entry) = area.get(at..at.saturating_add(len)).filter(|_| len >= 4) else {
            break;
        };
        match [a, b] {
            [b'S', b'P'] => rr.has_sp = true,
            [b'S', b'T'] => break,
            [b'R', b'E'] => rr.relocated = true,
            [b'C', b'L'] => rr.child_link = le32(entry, 4),
            [b'C', b'E'] => {
                if next.is_none()
                    && let (Some(block), Some(offset), Some(clen)) =
                        (le32(entry, 4), le32(entry, 12), le32(entry, 20))
                {
                    next = Some(Continuation {
                        block,
                        offset,
                        len: clen,
                    });
                }
            }
            [b'N', b'M'] => name(entry, acc),
            [b'P', b'X'] => posix(entry, rr),
            [b'S', b'L'] => symlink(entry, acc),
            [b'T', b'F'] => times(entry, rr),
            _ => {}
        }
        at = at.saturating_add(len);
    }
    next
}

fn name(entry: &[u8], acc: &mut Acc) {
    let Some(&flags) = entry.get(4) else { return };
    // Bits 1 and 2 name `.` and `..`: they belong to those records.
    if flags & 0b110 != 0 {
        return;
    }
    if let Some(piece) = entry.get(5..) {
        let room = MAX_NAME.saturating_sub(acc.name.len());
        acc.name
            .extend_from_slice(piece.get(..piece.len().min(room)).unwrap_or(&[]));
    }
}

fn posix(entry: &[u8], rr: &mut Rr) {
    if entry.len() < 36 {
        return;
    }
    rr.mode = le32(entry, 4);
    rr.uid = le32(entry, 20).unwrap_or(0);
    rr.gid = le32(entry, 28).unwrap_or(0);
}

fn symlink(entry: &[u8], acc: &mut Acc) {
    acc.link_seen = true;
    let mut at = 5usize;
    while let (Some(&flags), Some(&clen)) = (entry.get(at), entry.get(at.saturating_add(1))) {
        let start = at.saturating_add(2);
        let Some(content) = entry.get(start..start.saturating_add(usize::from(clen))) else {
            break;
        };
        at = start.saturating_add(usize::from(clen));
        let piece: &[u8] = if flags & 0b1000 != 0 {
            // Root: restart at "/".
            acc.link.clear();
            acc.link.push(b'/');
            acc.link_sep = false;
            acc.link_open = false;
            continue;
        } else if flags & 0b10 != 0 {
            b"."
        } else if flags & 0b100 != 0 {
            b".."
        } else {
            content
        };
        if acc.link.len().saturating_add(piece.len()) >= MAX_LINK {
            break;
        }
        if acc.link_sep && !acc.link_open {
            acc.link.push(b'/');
        }
        acc.link.extend_from_slice(piece);
        acc.link_sep = true;
        acc.link_open = flags & 1 != 0;
    }
}

fn times(entry: &[u8], rr: &mut Rr) {
    let Some(&flags) = entry.get(4) else { return };
    let long = flags & 0x80 != 0;
    let size = if long { 17 } else { 7 };
    let mut at = 5usize;
    for bit in 0..7u8 {
        if flags >> bit & 1 == 0 {
            continue;
        }
        let Some(raw) = entry.get(at..at.saturating_add(size)) else {
            return;
        };
        at = at.saturating_add(size);
        let value = if long {
            long_time(raw)
        } else {
            short_time(raw)
        };
        match bit {
            0 => rr.created = value,
            1 => rr.modified = value,
            2 => rr.accessed = value,
            _ => {}
        }
    }
}

/// The 7-byte record date: years since 1900, month, day, hour, minute,
/// second, offset from UTC in quarter hours.
pub fn short_time(raw: &[u8]) -> Option<Timestamp> {
    let &[y, mo, d, h, mi, s, off] = raw.get(..7)? else {
        return None;
    };
    if y == 0 && mo == 0 && d == 0 {
        return None;
    }
    civil_timestamp(
        1900_i64.saturating_add(i64::from(y)),
        i64::from(mo),
        i64::from(d),
        i64::from(h),
        i64::from(mi),
        i64::from(s),
        i64::from(i8::from_ne_bytes([off])),
    )
}

/// The 17-byte date: sixteen ASCII digits (`YYYYMMDDHHMMSSCC`) and an offset.
fn long_time(raw: &[u8]) -> Option<Timestamp> {
    let digits = raw.get(..16)?;
    let num = |from: usize, to: usize| -> Option<i64> {
        let mut v = 0i64;
        for &c in digits.get(from..to)? {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v
                .saturating_mul(10)
                .saturating_add(i64::from(c.wrapping_sub(b'0')));
        }
        Some(v)
    };
    let off = i64::from(i8::from_ne_bytes([*raw.get(16)?]));
    civil_timestamp(
        num(0, 4)?,
        num(4, 6)?,
        num(6, 8)?,
        num(8, 10)?,
        num(10, 12)?,
        num(12, 14)?,
        off,
    )
}
