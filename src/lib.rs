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
    pub fn new(hunks: Vec<Hunk<'a>>, truncation: Option<usize>) -> Self {
        Patch { hunks, truncation }
    }

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

    /// Returns the bytes that would be stored in an equivalent .ips file
    pub fn ips_file_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();

        push_all(&mut res, b"PATCH");

        for hunk in &self.hunks {
            let mut hunk_bytes = hunk.ips_file_bytes();
            res.append(&mut hunk_bytes);
        }

        push_all(&mut res, b"EOF");

        if let Some(truncation) = self.truncation {
            let mut truncation_bytes: [u8; 3] = [0; 3];
            BigEndian::write_u24(&mut truncation_bytes, truncation as u32);
            push_all(&mut res, &truncation_bytes)
        }

        return res;
    }

    /// Computes the new bytes of a ROM after patching its binary data with this IPS patch.
    /// If a hunk would write past the end of the ROM, the resulting ROM is extended to the necessary length.
    pub fn apply_to_rom(&self, rom_data: &[u8]) -> Vec<u8> {
        let mut new_rom_data = Vec::from(rom_data);

        for hunk in self.hunks.iter() {
            // checking this explicitly to avoid panicking when we call .copy_from_slice()
            if hunk.offset + hunk.payload.len() > new_rom_data.len() {
                // any value is fine since we're about to write over it, but padding with 0 seems easier
                new_rom_data.resize(hunk.offset + hunk.payload.len(), 0);
            }

            new_rom_data[hunk.offset..hunk.offset + hunk.payload.len()]
                .copy_from_slice(hunk.payload())
        }

        if let Some(truncation) = self.truncation() {
            new_rom_data.truncate(truncation)
        }

        new_rom_data
    }

    /// Overwrites the data in the given binary file by writing each hunk and truncating if specified.
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
    pub fn new(offset: usize, payload: Vec<u8>) -> Self {
        Hunk { offset, payload: Cow::from(payload) }
    }

    /// The offset in the patched file that the hunk should be applied to.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The data that should be overwritten at the offset.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the starting offset of this hunk as a 3-byte big-endian number.
    /// Used to write the contents of this patch to an IPS file.
    fn offset_bytes(&self) -> [u8; 3] {
        let mut buf: [u8; 3] = [0; 3];
        BigEndian::write_u24(&mut buf, self.offset as u32);
        return buf;
    }

    /// Returns the length of this hunk as a 2-byte big-endian number.
    /// Used to write the contents of this patch to an IPS file.
    fn length_bytes(&self) -> [u8; 2] {
        let mut buf: [u8; 2] = [0; 2];
        BigEndian::write_u16(&mut buf, self.payload.len() as u16);
        return buf;
    }

    /// Returns the bytes of this hunk as would be present in a binary IPS file containing this hunk.
    /// Used to write the contents of this patch to an IPS file.
    fn ips_file_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.reserve_exact(3 + 2 + self.payload.len());

        push_all(&mut res, &self.offset_bytes());
        push_all(&mut res, &self.length_bytes());
        push_all(&mut res, &*self.payload);

        return res;
    }


    /// Writes the bytes of this hunk to the correct spot of the given binary file.
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

/// Simple utility to append all of the bytes in the given slice onto the given vector.
/// This isn't super necessary but makes a lot of the code for writing files simpler.
fn push_all(vec: &mut Vec<u8>, data: &[u8]) {
    for byte in data {
        vec.push(*byte)
    }
}

mod tests {
    use crate::{Hunk, Patch, push_all};

    #[test]
    fn new() {
        let patch = Patch::new(vec![Hunk::new(0x013121, vec![0xFF, 0xEF])], None);
        assert_eq!(1, patch.hunks().len());
        assert_eq!(&[0xFF, 0xEF], patch.hunks()[0].payload());
        assert_eq!(0x013121, patch.hunks()[0].offset());
        assert_eq!(None, patch.truncation());
    }

    #[test]
    fn push_all_pushes_correctly() {
        let mut vec: Vec<u8> = vec![0x42, 0xFF, 0xAC];
        push_all(&mut vec, &[0xBA, 0xDA, 0x55]);
        push_all(&mut vec, b"EOF");
        assert_eq!(vec, vec![0x42, 0xFF, 0xAC, 0xBA, 0xDA, 0x55, b'E', b'O', b'F']);
    }

    #[test]
    fn parse_empty_patch() {
        let empty_ips_file_bytes = b"PATCHEOF";
        let empty_ips = Patch::parse(empty_ips_file_bytes);
        assert!(empty_ips.is_ok());
        let empty_ips = empty_ips.unwrap();
        assert!(empty_ips.hunks().is_empty());
        assert!(empty_ips.truncation().is_none());
    }

    #[test]
    fn parse_single_hunk_patch() {
        let single_hunk_ips_file_bytes = [
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x01, 0x31, 0x21, // offset 0x013121
            0x00, 0x02,   // length 0x0002
            0xFF, 0xEF, // 2 bytes of random data
            b'E', b'O', b'F',
        ];

        let patch = Patch::parse(&single_hunk_ips_file_bytes);
        assert!(patch.is_ok());
        let patch = patch.unwrap();
        assert_eq!(patch.hunks().len(), 1);
        assert_eq!(&*patch.hunks()[0].payload(), &[0xFF, 0xEF], "the bytes of the first hunk were parsed incorrectly");
        assert_eq!(patch.hunks()[0].offset(), 0x013121 as usize);
        assert!(patch.truncation().is_none());
    }

    #[test]
    fn parse_single_run_length_encoding_hunk_patch() {
        let single_hunk_ips_file_bytes = [
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x01, 0x31, 0x21, // offset 0x013121
            0x00, 0x00, // run length encoded hunk
            0x12, 0x34, // length 0x1234
            0xAB, // 1 byte to be repeated
            b'E', b'O', b'F',
        ];

        let patch = Patch::parse(&single_hunk_ips_file_bytes);
        assert!(patch.is_ok());
        let patch = patch.unwrap();
        assert_eq!(patch.hunks().len(), 1);
        assert_eq!(patch.hunks()[0].payload(), &[0xABu8; 0x1234], "the bytes of the first RLE hunk were parsed incorrectly");
        assert_eq!(patch.hunks()[0].offset(), 0x013121 as usize);
        assert!(patch.truncation().is_none());
    }


    #[test]
    fn parse_rejects_malformed_patches() {
        let malformed_patches = [
            vec![
                b'P', b'A', b'T', b'C', b'H',
                // add in a single hunk:
                0x01, 0x31, 0x21, // offset 0x013121
                0x00, 0x02,   // length 0x0002
                0xFF, // only 1 byte of data, should be two instead
                b'E', b'O', b'F',
            ],
            vec![
                b'P', b'A', b'T', b'C', b'H',
                // add in a single hunk:
                0x01, 0x31, 0x21, // offset 0x013121
                0x00, 0x02,   // length 0x0002
                0xFF, 0xAA, 0xEF, // 3 bytes of data, should be two instead
                b'E', b'O', b'F',
            ],
            vec![
                b'P', b'A', b'T', b'C', b'H',
                // add in a single RLE hunk:
                0x01, 0x31, 0x21, // offset 0x013121
                0x00, 0x00,   // RLE
                0xFF, 0xFF, // length 0xFFFF
                0x01, 0x23, // too many bytes for the RLE hunk!
                b'E', b'O', b'F',
            ],
            vec![
                b'P', b'A', b'T', b'C', b'H',
                // add in a single RLE hunk:
                0x01, 0x31, 0x21, // offset 0x013121
                0x00, 0x00,   // RLE
                0xFF, 0xFF, // length of 0xFFFF
                // missing byte of data!
                b'E', b'O', b'F',
            ],
            vec![
                // missing the PATCH header
                // add in a single hunk:
                0x01, 0x31, 0x21, 0x00, 0x02, 0xFF, 0xEF,
                b'E', b'O', b'F',
            ],
            vec![
                b'P', b'A', b'T', b'C', b'H',
                // add in a single hunk:
                0x01, 0x31, 0x21, 0x00, 0x02, 0xFF, 0xEF,
                // missing EOF footer
            ],
            vec![], // a totally empty file is invalid, it needs to at least have the header & footer
        ];

        for malformed_patch_bytes in malformed_patches {
            let patch = Patch::parse(&malformed_patch_bytes);
            assert!(patch.is_err());
        }
    }


    #[test]
    fn parse_single_hunk_patch_with_truncation() {
        let single_hunk_ips_file_bytes = [
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x01, 0x31, 0x21, // offset 0x013121
            0x00, 0x02,   // length 0x0002
            0xFF, 0xEF, // 2 bytes of random data
            b'E', b'O', b'F',
            0x01, 0x32, 0x40,
        ];

        let patch = Patch::parse(&single_hunk_ips_file_bytes);
        assert!(patch.is_ok());
        let patch = patch.unwrap();
        assert_eq!(patch.hunks().len(), 1);
        assert_eq!(patch.hunks()[0].payload(), &[0xFF, 0xEF], "the bytes of the first hunk were parsed incorrectly");
        assert_eq!(patch.hunks()[0].offset(), 0x013121 as usize);
        assert_eq!(patch.truncation(), Some(0x013240));
    }

    #[test]
    fn ips_round_trip_single_hunk_patch() {
        let input_bytes = vec![
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x01, 0x31, 0x21, // offset 0x013121
            0x00, 0x02,   // length 0x0002
            0xFF, 0xEF, // 2 bytes of random data
            b'E', b'O', b'F',
        ];

        let patch = Patch::parse(&input_bytes).unwrap();

        let output_bytes = patch.ips_file_bytes();

        assert_eq!(input_bytes, output_bytes);
    }

    #[test]
    fn applies_patch_with_two_hunks_with_truncation() {
        let ips_file_bytes = [
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x00, 0x00, 0x02, // offset at byte 2
            0x00, 0x02,   // length 2
            0xAB, 0xCD, // 2 bytes of random data
            // second hunk:
            0x00, 0x00, 0x0A, // offset at byte 10
            0x00, 0x03, // length 3
            0xBA, 0xDA, 0x55, // 3 bytes of random data
            b'E', b'O', b'F',
            // truncate to 16 bytes:
            0x00, 0x00, 0x10,
        ];

        let patch = Patch::parse(&ips_file_bytes).unwrap();

        let patched_rom = patch.apply_to_rom(&[0xFF; 32]);

        assert_eq!(patched_rom, vec![
            0xFF, 0xFF, 0xAB, 0xCD, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBA, 0xDA, 0x55, 0xFF, 0xFF, 0xFF,
        ]);
    }


    #[test]
    fn applies_patch_with_run_length_encoding() {
        let ips_file_bytes = [
            b'P', b'A', b'T', b'C', b'H',
            // add in a single hunk:
            0x00, 0x00, 0x02, // offset at byte 2
            0x00, 0x00,   // run length encoding
            0x00, 0x05,   // apply for 5 bytes
            0xA1, // some byte to repeat
            b'E', b'O', b'F',
        ];

        let patch = Patch::parse(&ips_file_bytes).unwrap();

        let patched_rom = patch.apply_to_rom(&[0xFF; 32]);

        assert_eq!(patched_rom, vec![
            0xFF, 0xFF, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
    }
}