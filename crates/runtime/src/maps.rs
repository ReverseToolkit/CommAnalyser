use std::fmt;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::range::Range;

/// Access flags for one `/proc/<pid>/maps` entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub shared: bool,
}

impl Perms {
    #[inline]
    pub const fn is_readable(&self) -> bool {
        self.read
    }

    #[inline]
    pub const fn is_writable(&self) -> bool {
        self.write
    }

    #[inline]
    pub const fn is_executable(&self) -> bool {
        self.exec
    }
}

impl fmt::Debug for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = [b'-'; 4];
        if self.read {
            s[0] = b'r';
        }
        if self.write {
            s[1] = b'w';
        }
        if self.exec {
            s[2] = b'x';
        }
        s[3] = if self.shared { b's' } else { b'p' };
        // SAFETY: all bytes are ASCII.
        f.write_str(std::str::from_utf8(&s).unwrap())
    }
}

/// One line from `/proc/<pid>/maps`.
#[derive(Clone, PartialEq, Eq)]
pub struct Mapping {
    pub range: Range,
    pub perms: Perms,
    pub offset: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub path: Option<String>,
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:?} off={:#x} dev={:02x}:{:02x} ino={} {}",
            self.range,
            self.perms,
            self.offset,
            self.dev_major,
            self.dev_minor,
            self.inode,
            self.path.as_deref().unwrap_or("")
        )
    }
}

impl Mapping {
    /// Parse one line of `/proc/<pid>/maps`.
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            return Err(Error::Parse("empty maps line".into()));
        }

        // pathnames may contain spaces, so split into at most 6 fields.
        let mut fields = line.splitn(6, ' ');
        let range = fields
            .next()
            .ok_or_else(|| Error::Parse(format!("missing range: {line:?}")))?;
        let perms = fields
            .next()
            .ok_or_else(|| Error::Parse(format!("missing perms: {line:?}")))?;
        let offset = fields
            .next()
            .ok_or_else(|| Error::Parse(format!("missing offset: {line:?}")))?;
        let dev = fields
            .next()
            .ok_or_else(|| Error::Parse(format!("missing dev: {line:?}")))?;
        let inode = fields
            .next()
            .ok_or_else(|| Error::Parse(format!("missing inode: {line:?}")))?;
        let path = fields.next().map(str::trim_start).filter(|s| !s.is_empty());

        let (start, end) = range
            .split_once('-')
            .ok_or_else(|| Error::Parse(format!("bad range: {range:?}")))?;
        let start = usize::from_str_radix(start, 16)
            .map_err(|_| Error::Parse(format!("bad range start: {start:?}")))?;
        let end = usize::from_str_radix(end, 16)
            .map_err(|_| Error::Parse(format!("bad range end: {end:?}")))?;
        if end < start {
            return Err(Error::Parse(format!("reversed range: {range:?}")));
        }

        let perms = parse_perms(perms)?;
        let offset = u64::from_str_radix(offset, 16)
            .map_err(|_| Error::Parse(format!("bad offset: {offset:?}")))?;
        let (major, minor) = dev
            .split_once(':')
            .ok_or_else(|| Error::Parse(format!("bad dev: {dev:?}")))?;
        let dev_major = u32::from_str_radix(major, 16)
            .map_err(|_| Error::Parse(format!("bad dev major: {major:?}")))?;
        let dev_minor = u32::from_str_radix(minor, 16)
            .map_err(|_| Error::Parse(format!("bad dev minor: {minor:?}")))?;
        let inode = inode
            .parse::<u64>()
            .map_err(|_| Error::Parse(format!("bad inode: {inode:?}")))?;

        Ok(Self {
            range: Range::new(start, end),
            perms,
            offset,
            dev_major,
            dev_minor,
            inode,
            path: path.map(str::to_owned),
        })
    }

    /// Path with the kernel's ` (deleted)` suffix stripped.
    pub fn clean_path(&self) -> Option<&str> {
        self.path
            .as_deref()
            .map(|s| s.strip_suffix(" (deleted)").unwrap_or(s))
    }
}

fn parse_perms(s: &str) -> Result<Perms> {
    let bytes = s.as_bytes();
    if bytes.len() != 4 {
        return Err(Error::Parse(format!("bad perms: {s:?}")));
    }
    let read = match bytes[0] {
        b'r' => true,
        b'-' => false,
        _ => return Err(Error::Parse(format!("bad perms: {s:?}"))),
    };
    let write = match bytes[1] {
        b'w' => true,
        b'-' => false,
        _ => return Err(Error::Parse(format!("bad perms: {s:?}"))),
    };
    let exec = match bytes[2] {
        b'x' => true,
        b'-' => false,
        _ => return Err(Error::Parse(format!("bad perms: {s:?}"))),
    };
    let shared = match bytes[3] {
        b's' => true,
        b'p' => false,
        _ => return Err(Error::Parse(format!("bad perms: {s:?}"))),
    };
    Ok(Perms {
        read,
        write,
        exec,
        shared,
    })
}

/// Parse the full contents of a maps file.
pub fn parse_maps(text: &str) -> Result<Vec<Mapping>> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(Mapping::parse)
        .collect()
}

/// Read `/proc/<pid>/maps`.
pub fn read_maps(pid: u32) -> Result<Vec<Mapping>> {
    let path = format!("/proc/{pid}/maps");
    let text = fs::read_to_string(&path)?;
    parse_maps(&text)
}

/// Read `/proc/self/maps`.
pub fn read_self_maps() -> Result<Vec<Mapping>> {
    let text = fs::read_to_string("/proc/self/maps")?;
    parse_maps(&text)
}

/// Find the mapping containing `addr` from the current process.
pub fn self_mapping_containing(addr: usize) -> Result<Option<Mapping>> {
    Ok(read_self_maps()?
        .into_iter()
        .find(|m| m.range.contains(addr)))
}

/// Find the first module mapping whose path ends with `name`.
pub fn self_mapping_by_name(name: &str) -> Result<Option<Mapping>> {
    Ok(read_self_maps()?.into_iter().find(|m| {
        m.clean_path()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == name)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_line() {
        let m = Mapping::parse("7f8e00000000-7f8e00021000 r-xp 00000000 fd:01 12345 /apex/com.android.art/lib64/libart.so").unwrap();
        assert_eq!(m.range, Range::new(0x7f8e00000000, 0x7f8e00021000));
        assert!(m.perms.read && m.perms.exec && !m.perms.write && !m.perms.shared);
        assert_eq!(m.offset, 0);
        assert_eq!((m.dev_major, m.dev_minor), (0xfd, 0x01));
        assert_eq!(m.inode, 12345);
        assert_eq!(
            m.clean_path(),
            Some("/apex/com.android.art/lib64/libart.so")
        );
    }

    #[test]
    fn parse_path_with_spaces() {
        let m =
            Mapping::parse("1000-2000 rw-p 00000000 00:00 0 /data/app/foo bar/base.apk").unwrap();
        assert_eq!(m.clean_path(), Some("/data/app/foo bar/base.apk"));
    }

    #[test]
    fn parse_anonymous_and_deleted() {
        let m = Mapping::parse("1000-2000 rw-p 00000000 00:00 0 [anon:dalvik-main space]").unwrap();
        assert_eq!(m.path.as_deref(), Some("[anon:dalvik-main space]"));
        let m =
            Mapping::parse("1000-2000 r-xp 00000000 fd:01 2 /data/libfoo.so (deleted)").unwrap();
        assert_eq!(m.clean_path(), Some("/data/libfoo.so"));
    }

    #[test]
    fn self_maps_are_readable() {
        let maps = read_self_maps().unwrap();
        assert!(!maps.is_empty());
        assert!(maps.iter().any(|m| m.perms.exec));
        assert!(maps.iter().any(|m| m.range.contains(maps[0].range.start)));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Mapping::parse("nope").is_err());
        assert!(Mapping::parse("2000-1000 r-xp 0 00:00 0 x").is_err());
        assert!(Mapping::parse("1000-2000 q-xp 0 00:00 0 x").is_err());
    }
}
