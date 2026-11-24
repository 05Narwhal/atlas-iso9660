// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Builds ISO 9660 images for tests and fuzz seeds.
//!
//! Blocks are 2048 bytes. The layout is the system area, the primary
//! descriptor, the Joliet descriptor (when asked for), the terminator, the
//! folders of each tree, the continuation areas, then the files' data. Every
//! record has the date [`UNIX_SECONDS`] (2020-03-04 05:06:07 at UTC+1).

/// Bytes of a block.
pub const BLOCK: usize = 2048;
/// The date every record carries, in UTC.
pub const UNIX_SECONDS: i64 = 1_583_294_767;
/// What a Rock Ridge `TF` entry says for modification: 2021-06-07 08:09:10 UTC.
pub const TF_SECONDS: i64 = 1_623_053_350;
/// Names longer than this go to a continuation area in a Rock Ridge tree.
pub const CE_NAME_LEN: usize = 120;

/// What an entry is.
#[derive(Debug, Clone)]
pub enum Kind {
    File(Vec<u8>),
    /// One file in several extents.
    Multi(Vec<Vec<u8>>),
    Dir(Vec<Entry>),
    Link(String),
}

/// One entry to build.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub hidden: bool,
}

impl Entry {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self::new(name, Kind::File(data.to_vec()))
    }
    pub fn multi(name: &str, parts: &[&[u8]]) -> Self {
        Self::new(
            name,
            Kind::Multi(parts.iter().map(|p| p.to_vec()).collect()),
        )
    }
    pub fn dir(name: &str, kids: Vec<Entry>) -> Self {
        Self::new(name, Kind::Dir(kids))
    }
    pub fn link(name: &str, target: &str) -> Self {
        Self::new(name, Kind::Link(target.to_owned()))
    }
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }
    fn new(name: &str, kind: Kind) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            hidden: false,
        }
    }
}

/// Which extras the image has.
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts {
    pub rock_ridge: bool,
    pub joliet: bool,
}

struct Node {
    name: String,
    hidden: bool,
    kind: Kind,
    kids: Vec<usize>,
    parent: usize,
    ext: [u32; 2],
    parts: Vec<(u32, u32)>,
    ce: u32,
}

fn flatten(entries: &[Entry], parent: usize, arena: &mut Vec<Node>) -> Vec<usize> {
    let mut ids = Vec::new();
    for e in entries {
        let id = arena.len();
        arena.push(Node {
            name: e.name.clone(),
            hidden: e.hidden,
            kind: e.kind.clone(),
            kids: Vec::new(),
            parent,
            ext: [0; 2],
            parts: Vec::new(),
            ce: 0,
        });
        if let Kind::Dir(kids) = &e.kind {
            let k = flatten(kids, id, arena);
            arena[id].kids = k;
        }
        ids.push(id);
    }
    ids
}

fn both32(v: u32) -> [u8; 8] {
    let mut o = [0u8; 8];
    o[..4].copy_from_slice(&v.to_le_bytes());
    o[4..].copy_from_slice(&v.to_be_bytes());
    o
}

fn both16(v: u16) -> [u8; 4] {
    let mut o = [0u8; 4];
    o[..2].copy_from_slice(&v.to_le_bytes());
    o[2..].copy_from_slice(&v.to_be_bytes());
    o
}

const DATE: [u8; 7] = [120, 3, 4, 5, 6, 7, 4];

/// A directory record.
fn record(name: &[u8], extent: u32, len: u32, flags: u8, su: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 33];
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(len));
    r[18..25].copy_from_slice(&DATE);
    r[25] = flags;
    r[28..32].copy_from_slice(&both16(1));
    r[32] = name.len() as u8;
    r.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        r.push(0);
    }
    r.extend_from_slice(su);
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r[0] = r.len() as u8;
    r
}

fn iso_name(name: &str, dir: bool) -> Vec<u8> {
    let mut n: String = name
        .chars()
        .take(30)
        .collect::<String>()
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !dir {
        if !n.contains('.') {
            n.push('.');
        }
        n.push_str(";1");
    }
    n.into_bytes()
}

fn joliet_name(name: &str, dir: bool) -> Vec<u8> {
    let short: String = name.chars().take(60).collect();
    let full = if dir { short } else { format!("{short};1") };
    full.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn rr_entries(n: &Node, with_ce: bool) -> (Vec<u8>, Vec<u8>) {
    // (entries in the record, entries in the continuation area)
    let mut nm = vec![b'N', b'M', (5 + n.name.len()) as u8, 1, 0];
    nm.extend_from_slice(n.name.as_bytes());
    let mode: u32 = match n.kind {
        Kind::Dir(_) => 0o040_755,
        Kind::Link(_) => 0o120_777,
        _ => 0o100_644,
    };
    let mut px = vec![b'P', b'X', 36, 1];
    for v in [mode, 1, 1000, 100] {
        px.extend_from_slice(&both32(v));
    }
    let mut tf = vec![b'T', b'F', 12, 1, 0x02];
    tf.extend_from_slice(&[121, 6, 7, 8, 9, 10, 0]);
    let mut here = Vec::new();
    let mut ce_area = Vec::new();
    if with_ce {
        ce_area.extend_from_slice(&nm);
        let mut ce = vec![b'C', b'E', 28, 1];
        ce.extend_from_slice(&both32(n.ce));
        ce.extend_from_slice(&both32(0));
        ce.extend_from_slice(&both32(ce_area.len() as u32));
        here.extend_from_slice(&px);
        here.extend_from_slice(&tf);
        here.extend_from_slice(&ce);
    } else {
        here.extend_from_slice(&nm);
        here.extend_from_slice(&px);
        here.extend_from_slice(&tf);
    }
    if let Kind::Link(target) = &n.kind {
        let mut comps = Vec::new();
        if target.starts_with('/') {
            comps.extend_from_slice(&[8, 0]);
        }
        for part in target.split('/').filter(|p| !p.is_empty()) {
            let flags = match part {
                "." => 2,
                ".." => 4,
                _ => 0,
            };
            let body = if flags == 0 { part.as_bytes() } else { &[][..] };
            comps.extend_from_slice(&[flags, body.len() as u8]);
            comps.extend_from_slice(body);
        }
        let mut sl = vec![b'S', b'L', (5 + comps.len()) as u8, 1, 0];
        sl.extend_from_slice(&comps);
        here.extend_from_slice(&sl);
    }
    (here, ce_area)
}

/// The bytes of folder `idx` in `tree` (0 primary, 1 Joliet), whole blocks.
fn dir_bytes(arena: &[Node], idx: usize, tree: usize, opts: &Opts, lens: &[[u32; 2]]) -> Vec<u8> {
    let rr = tree == 0 && opts.rock_ridge;
    let node = &arena[idx];
    let len_of = |i: usize| -> u32 { lens[i][tree] };
    let mut recs: Vec<Vec<u8>> = Vec::new();
    let sp: Vec<u8> = if rr {
        vec![b'S', b'P', 7, 1, 0xBE, 0xEF, 0]
    } else {
        Vec::new()
    };
    recs.push(record(&[0], node.ext[tree], len_of(idx), FLAG_DIR, &sp));
    let up = if idx == 0 { 0 } else { node.parent };
    recs.push(record(&[1], arena[up].ext[tree], len_of(up), FLAG_DIR, &[]));
    for &k in &node.kids {
        let c = &arena[k];
        let is_dir = matches!(c.kind, Kind::Dir(_));
        let name = if tree == 1 {
            joliet_name(&c.name, is_dir)
        } else {
            iso_name(&c.name, is_dir)
        };
        let su = if rr {
            rr_entries(c, c.name.len() > CE_NAME_LEN).0
        } else {
            Vec::new()
        };
        let hidden = u8::from(c.hidden);
        match &c.kind {
            Kind::Dir(_) => recs.push(record(
                &name,
                c.ext[tree],
                len_of(k),
                FLAG_DIR | hidden,
                &su,
            )),
            _ => {
                let n = c.parts.len().max(1);
                for i in 0..n {
                    let (e, l) = c.parts.get(i).copied().unwrap_or((0, 0));
                    let more = if i + 1 < n { 0x80 } else { 0 };
                    let s = if i == 0 { su.as_slice() } else { &[][..] };
                    recs.push(record(&name, e, l, hidden | more, s));
                }
            }
        }
    }
    let mut out: Vec<u8> = Vec::new();
    for r in recs {
        let room = BLOCK - out.len() % BLOCK;
        if r.len() > room {
            out.resize(out.len() + room, 0);
        }
        out.extend_from_slice(&r);
    }
    out.resize(out.len().div_ceil(BLOCK).max(1) * BLOCK, 0);
    out
}

const FLAG_DIR: u8 = 2;

fn descriptor(kind: u8, label: &str, joliet: bool, root: &[u8], total_blocks: u32) -> Vec<u8> {
    let mut d = vec![0u8; BLOCK];
    d[0] = kind;
    d[1..6].copy_from_slice(b"CD001");
    d[6] = 1;
    let id: Vec<u8> = if joliet {
        label.encode_utf16().flat_map(u16::to_be_bytes).collect()
    } else {
        label.as_bytes().to_vec()
    };
    let fill: &[u8] = if joliet { &[0, 0x20] } else { &[0x20] };
    let mut field = id;
    field.truncate(32);
    while field.len() < 32 {
        field.extend_from_slice(fill);
    }
    d[40..72].copy_from_slice(&field[..32]);
    d[80..88].copy_from_slice(&both32(total_blocks));
    if joliet {
        d[88..91].copy_from_slice(b"%/E");
    }
    d[120..124].copy_from_slice(&both16(1));
    d[128..132].copy_from_slice(&both16(BLOCK as u16));
    d[156..190].copy_from_slice(root);
    d
}

/// Builds the image.
pub fn build(root: &[Entry], opts: &Opts) -> Vec<u8> {
    let mut arena = vec![Node {
        name: String::new(),
        hidden: false,
        kind: Kind::Dir(Vec::new()),
        kids: Vec::new(),
        parent: 0,
        ext: [0; 2],
        parts: Vec::new(),
        ce: 0,
    }];
    arena[0].kids = flatten(root, 0, &mut arena);
    let trees = if opts.joliet { 2 } else { 1 };
    let mut next = 16 + trees as u32 + 1;
    // Sizes first: record sizes do not depend on extent values.
    let mut lens = vec![[0u32; 2]; arena.len()];
    for t in 0..trees {
        for i in 0..arena.len() {
            if matches!(arena[i].kind, Kind::Dir(_)) {
                lens[i][t] = dir_bytes(&arena, i, t, opts, &lens).len() as u32;
                arena[i].ext[t] = next;
                next += lens[i][t] / BLOCK as u32;
            }
        }
    }
    #[allow(clippy::needless_range_loop)]
    for i in 0..arena.len() {
        if opts.rock_ridge && arena[i].name.len() > CE_NAME_LEN {
            arena[i].ce = next;
            next += 1;
        }
        let sizes: Vec<usize> = match &arena[i].kind {
            Kind::File(d) => vec![d.len()],
            Kind::Multi(p) => p.iter().map(Vec::len).collect(),
            _ => Vec::new(),
        };
        for s in sizes {
            arena[i].parts.push((next, s as u32));
            next += s.div_ceil(BLOCK) as u32;
        }
    }
    let mut image = vec![0u8; next as usize * BLOCK];
    let mut put = |block: u32, bytes: &[u8]| {
        let at = block as usize * BLOCK;
        image[at..at + bytes.len()].copy_from_slice(bytes);
    };
    // Folders. Their records carry the real lengths now, so the dry-run
    // length lookups are replaced by the stored ones.
    for t in 0..trees {
        for i in 0..arena.len() {
            if matches!(arena[i].kind, Kind::Dir(_)) {
                let bytes = dir_bytes(&arena, i, t, opts, &lens);
                put(arena[i].ext[t], &bytes);
            }
        }
    }
    for (i, n) in arena.iter().enumerate() {
        let data: Vec<&[u8]> = match &n.kind {
            Kind::File(d) => vec![d.as_slice()],
            Kind::Multi(p) => p.iter().map(Vec::as_slice).collect(),
            _ => Vec::new(),
        };
        for (d, (ext, _)) in data.iter().zip(&n.parts) {
            put(*ext, d);
        }
        if n.ce != 0 {
            put(n.ce, &rr_entries(n, true).1);
        }
        let _ = i;
    }
    let root_rec = |t: usize| record(&[0], arena[0].ext[t], lens[0][t], FLAG_DIR, &[]);
    put(16, &descriptor(1, "ATLAS", false, &root_rec(0), next));
    if opts.joliet {
        put(17, &descriptor(2, "Atlas Ünï", true, &root_rec(1), next));
    }
    let mut term = vec![0u8; BLOCK];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    put(16 + trees as u32, &term);
    image
}
