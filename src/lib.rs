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
use std::fs::File;
use std::io::{Seek, Write};
use std::io::SeekFrom;

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

    pub fn ips_file_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();

        push_all(&mut res, b"PATCH");

        for hunk in &self.hunks {
            let mut hunk_bytes = hunk.ips_file_bytes();
            res.append(&mut hunk_bytes);
        }

        push_all(&mut res, b"EOF");

        return res;
    }

    pub fn apply_to_rom(&self, rom_data: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut new_rom_data = Vec::from(rom_data);

        for hunk in self.hunks.iter() {
            // checking this explicitly to avoid panicking when we call .copy_from_slice()
            if hunk.offset + hunk.payload.len() > new_rom_data.len() {
                return Err(Error("Patch data in hunk extended past the end of the ROM".to_string()));
            }

            new_rom_data[hunk.offset..hunk.offset + hunk.payload.len()]
                .copy_from_slice(hunk.payload())
        }

        if let Some(truncation) = self.truncation() {
            new_rom_data.truncate(truncation)
        }

        Ok(new_rom_data)
    }

    pub fn write_to_rom(&self, rom_file: &mut File) -> std::io::Result<()> {
        for hunk in self.hunks.iter() {
            hunk.write_to_rom(rom_file)?
        }

        if let Some(truncation) = self.truncation() {
            rom_file.set_len(truncation as u64)?;
        }

        return std::io::Result::Ok(());
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

    // returns the starting offset of this hunk as a 2-byte big-endian number
    fn offset_bytes(&self) -> [u8; 3] {
        let mut buf: [u8; 3] = [0; 3];
        BigEndian::write_u24(&mut buf, self.offset as u32);
        return buf;
    }

    // returns the length of this hunk as a 2-byte big-endian number
    fn length_bytes(&self) -> [u8; 2] {
        let mut buf: [u8; 2] = [0; 2];
        BigEndian::write_u16(&mut buf, self.payload.len() as u16);
        return buf;
    }

    fn ips_file_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.reserve_exact(3 + 2 + self.payload.len());

        push_all(&mut res, &self.offset_bytes());
        push_all(&mut res, &self.length_bytes());
        push_all(&mut res, &*self.payload);

        return res;
    }

    fn write_to_rom<T: Seek + Write>(&self, rom_file: &mut T) -> std::io::Result<()> {
        rom_file.seek(SeekFrom::Start(self.offset() as u64))?;
        rom_file.write_all(self.payload())?;

        return std::io::Result::Ok(());
    }
}

fn ips(input: &[u8]) -> IResult<&[u8], Patch> {
    let (input, _) = tag(b"PATCH")(input)?;
    let (input, hunks) = many0(hunk)(input)?;
    let (input, _) = tag(b"EOF")(input)?;

    let (input, truncation) = opt(be_int(3))(input)?;

    Ok((input, Patch {
        hunks,
        truncation,
    }))
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

fn push_all(vec: &mut Vec<u8>, data: &[u8]) {
    for byte in data {
        vec.push(*byte)
    }
}