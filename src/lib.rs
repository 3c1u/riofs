//! Handles an ShiinaRio archive (.WAR)

mod decrypt;
mod error;
#[cfg(test)]
mod test;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

use std::fs::File;
use std::path::Path;

use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};

pub struct WillArchive<A> {
    pub(crate) archive: BufReader<A>,
    pub(crate) metadata: WarcMetadata,
}

#[derive(Default, Clone)]
pub(crate) struct WarcMetadata {
    index_offset: u32,
    entries: Vec<WarcEntry>,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct WarcEntry {
    pub(crate) filename: String,
    pub(crate) offset: u32,
    pub(crate) size: u32,
    pub(crate) size_unpacked: u32,
    pub(crate) timestamp: i64,
    pub(crate) flags: u32,
}

impl WillArchive<File> {
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let archive = File::open(path)?;
        let archive = BufReader::new(archive);

        let mut archive = WillArchive {
            archive,
            metadata: Default::default(),
        };

        archive.read_metadata()?;

        Ok(archive)
    }
}

impl WillArchive<Cursor<Vec<u8>>> {
    pub fn from_bytes_owned(bytes: Vec<u8>) -> Result<Self> {
        let mut archive = WillArchive {
            archive: BufReader::new(Cursor::new(bytes)),
            metadata: Default::default(),
        };

        archive.read_metadata()?;

        Ok(archive)
    }
}

impl<'a> WillArchive<Cursor<&'a [u8]>> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let mut archive = WillArchive {
            archive: BufReader::new(Cursor::new(bytes)),
            metadata: Default::default(),
        };

        archive.read_metadata()?;

        Ok(archive)
    }
}

use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;

impl<A> WillArchive<A>
where
    A: Read + Seek,
{
    fn read_metadata(&mut self) -> Result<()> {
        let rdr = &mut self.archive;

        // check the archive magic
        let mut warc = [0u8; 8];
        rdr.read_exact(&mut warc)?;

        // check magic header
        if b"WARC " != &warc[..5] {
            return Err(Error::IncorrectMagicHeader);
        }

        let version = (warc[5] - b'0', warc[7] - b'0');
        if (1, 7) != version {
            return Err(Error::UnsupportedVersion);
        }

        // initialize decryptor
        use decrypt::Decoder;
        let mut decryptor = Decoder::new(version);

        // load file index
        let index_offset = 0xF182AD82 ^ rdr.read_u32::<LittleEndian>()?;
        let file_tail = rdr.seek(SeekFrom::End(0))? as usize;
        let index_size = decrypt::get_index_size(version).min(file_tail - index_offset as usize);
        let mut index_buf = vec![0u8; index_size];

        rdr.seek(SeekFrom::Start(index_offset as u64))?;
        rdr.read_exact(&mut index_buf)?;

        decryptor.decrypt_index(&mut index_buf, index_offset);

        assert_eq!(index_buf[8], 0x78, "decode failed");

        let mut decoder = ZlibDecoder::new(Cursor::new(&mut index_buf[8..]));

        let mut filename_buf = vec![0u8; decrypt::ENTRY_NAME_SIZE];

        loop {
            // read filename
            decoder.read_exact(&mut filename_buf)?;

            let filename = String::from_utf8(filename_buf.clone()).unwrap();
            let offset = decoder.read_u32::<LittleEndian>()?;
            let size = decoder.read_u32::<LittleEndian>()?;
            let size_unpacked = decoder.read_u32::<LittleEndian>()?;
            let timestamp = decoder.read_i64::<LittleEndian>()?;
            let flags = decoder.read_u32::<LittleEndian>()?;

            if filename.len() == 0 {
                break;
            }

            let entry = WarcEntry {
                filename,
                size,
                offset,
                size_unpacked,
                timestamp,
                flags,
            };

            println!("file added: {:#?}", entry);
        }

        Ok(())
    }
}
