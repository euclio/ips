//! Parser for the IPS patch format.
//!
//! Handles run-length encoded hunks as well as the truncation extension.
//!
//! # Example
//!
//! Patching a ROM from an IPS file:
//!
//! ```no_run
//! use std::fs::{self, File};
//! use std::io::{Seek, SeekFrom, Write};
//!
//! use ips::Patch;
//!
//! let mut rom = File::open("Super Metroid.sfc")?;
//! let patch_contents = fs::read("Hyper Metroid.ips")?;
//! let patch = Patch::parse(&patch_contents)?;
//!
//! for hunk in patch.hunks() {
//!     rom.seek(SeekFrom::Start(hunk.offset() as u64))?;
//!     rom.write_all(hunk.payload())?;
//! }
//!
//! if let Some(truncation) = patch.truncation() {
//!     rom.set_len(truncation as u64)?;
//! }
//!
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use std::borrow::Cow;
use std::fmt;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use nom::bytes::complete::{tag, take};
use nom::combinator::opt;
use nom::multi::many0;
use nom::IResult;

/// The contents of an IPS patch.
#[derive(Debug)]
pub struct Patch<'a> {
    hunks: Vec<Hunk<'a>>,
    truncation: Option<usize>,
}

impl<'a> Patch<'a> {
    /// Parses an IPS patch from bytes.
    pub fn parse(input: &[u8]) -> Result<Patch, Error> {
        match ips(input) {
            Ok((_, patch)) => Ok(patch),
            Err(e) => Err(Error(e.to_string())),
        }
    }

    /// Returns the hunks in the patch.
    pub fn hunks(&self) -> &[Hunk<'a>] {
        &self.hunks
    }

    /// Some IPS files indicate a length that the final patched file should be truncated to.
    pub fn truncation(&self) -> Option<usize> {
        self.truncation
    }
}

/// IPS parsing error.
#[derive(Debug)]
pub struct Error(String);

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A patch hunk.
#[derive(Debug)]
pub struct Hunk<'a> {
    offset: usize,
    payload: Cow<'a, [u8]>,
}

impl<'a> Hunk<'a> {
    /// The offset in the patched file that the hunk should be applied to.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The data that should be overwritten at the offset.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

fn ips(input: &[u8]) -> IResult<&[u8], Patch> {
    let (input, _) = tag(b"PATCH")(input)?;
    let (input, hunks) = many0(hunk)(input)?;
    let (input, _) = tag(b"EOF")(input)?;

    let (input, truncation) = opt(be_int(3))(input)?;

    Ok((input, Patch { hunks, truncation }))
}

fn hunk(input: &[u8]) -> IResult<&[u8], Hunk> {
    let (input, offset) = be_int(3)(input)?;
    let (input, len) = be_int(2)(input)?;

    let (input, payload) = if len == 0 {
        // Run-length encoding
        let (input, len) = be_int(2)(input)?;
        let (input, payload) = take(1usize)(input)?;

        (input, Cow::from(vec![payload[0]; len]))
    } else {
        let (input, payload) = take(len)(input)?;
        (input, Cow::from(payload))
    };

    Ok((input, Hunk { offset, payload }))
}

fn be_int(len: usize) -> impl Fn(&[u8]) -> IResult<&[u8], usize> {
    move |input: &[u8]| {
        let (input, bytes) = take(len)(input)?;
        Ok((input, BigEndian::read_uint(bytes, len) as usize))
    }
}
