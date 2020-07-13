/*
 * copied from `vn-tools/arc_unpacker`;
 * i am not a big fan of GPL though...
 *
 * plugin_manager.add(
 *     "nukitashi",
 *     "Nukige Mitai na Shima ni Sunderu Watashi wa Dou Surya Ii Desu ka?",
 *     []()
 *     {
 *         auto p = std::make_shared<warc::Plugin>();
 *         p->version = 2500;
 *         p->entry_name_size = 0x20;
 *         p->region_image = read_etc_image("region.png");
 *         p->logo_data = read_etc_file("logo_nukitashi.jpg");
 *         p->initial_crypt_base_keys
 *             = {0x90B989AF, 0x60BA6AB8, 0x86B9E6B9, 0xF3B999B9, 0xF2B9BCA8};
 *         p->extra_crypt = std::make_unique<NukiTashiExtraCrypt>();
 *         p->crc_crypt_source = read_etc_file("table4.bin");
 *         return p;
 *     });
*/

mod helper;

#[derive(Default)]
pub struct RioRng(u32);

#[derive(Default)]
pub(crate) struct Decoder {
    rng: RioRng,
    scheme: Scheme,
}

#[derive(Clone)]
pub(crate) struct Scheme {
    key: Vec<u8>,
    shiina_image: Vec<u8>,
    region: Vec<u8>,
    helper_key: Vec<u32>,
    decode_bin: Vec<u8>,
    version: (u8, u8),
    scheme_version: u32,
}

impl Default for Scheme {
    fn default() -> Scheme {
        use std::io::Cursor;

        let region: &[u8] = include_bytes!("../bin/region.png");
        let decoder = png::Decoder::new(Cursor::new(region));
        let (info, mut rdr) = decoder.read_info().unwrap();
        let mut region = vec![0u8; info.buffer_size()];
        rdr.next_frame(&mut region).unwrap();

        Self {
            version: (1, 7),
            scheme_version: 2500,
            region,
            shiina_image: include_bytes!("../bin/logo_nukitashi.jpg").to_vec(),
            helper_key: vec![0x90B989AF, 0x60BA6AB8, 0x86B9E6B9, 0xF3B999B9, 0xF2B9BCA8],
            key: b"Crypt Type 20011002 - Copyright(C) 2000 Y.Yamada/STUDIO \x82\xE6\x82\xB5\x82\xAD\x82\xF1".to_vec(),
            decode_bin: vec![],
        }
    }
}

pub trait Encode {
    fn encode<R>(
        data: &mut [u8],
        version: (u8, u8),
        key: &[u8],
        key_initial_position: u32,
        rng: &mut R,
    ) where
        R: Rng;
}

pub trait Rng {
    fn next_rand(&mut self) -> u32;
    fn peek(&self) -> u32;
    fn seed(&mut self, seed: u32);
}

pub struct Decrypter;

impl Encode for Decrypter {
    fn encode<R>(
        data: &mut [u8],
        version: (u8, u8),
        key: &[u8],
        key_initial_position: u32,
        rng: &mut R,
    ) where
        R: Rng,
    {
        let mut key_offset = 0usize;
        let mut key_position = key_initial_position as usize;

        for x in data.iter_mut().skip(2) {
            if version > (1, 2) {
                *x ^= (rng.next_rand() as f64 / 16777216.0) as u8;
            }

            *x = x.rotate_right(1);

            *x ^= key[key_offset] ^ key[key_position];
            key_offset += 1;

            key_position = *x as usize % key.len();

            if key_offset >= key.len() {
                key_offset = 0;
            }
        }
    }
}

impl Decoder {
    pub fn new(version: (u8, u8)) -> Self {
        Self {
            rng: RioRng::default(),
            scheme: Scheme {
                version,
                ..Scheme::default()
            },
        }
    }
}

// rng
impl Rng for RioRng {
    fn next_rand(&mut self) -> u32 {
        use std::num::Wrapping;

        self.0 = (Wrapping(1566083941) * Wrapping(self.0) + Wrapping(1)).0;
        self.0
    }

    fn peek(&self) -> u32 {
        self.0
    }

    fn seed(&mut self, seed: u32) {
        self.0 = seed;
    }
}

impl Decoder {
    pub fn xor_index(&self, index: &mut [u8], offset: u32) {
        let offset = offset.to_le_bytes();

        for i in 0..(index.len() >> 2) {
            let buf = &mut index[(i << 2)..];
            for j in 0..4 {
                buf[j] ^= offset[j];
            }
        }

        if self.scheme.version >= (1, 7) {
            let version = !(self.scheme.version.0 * 100 + self.scheme.version.1);
            for x in index {
                *x ^= version;
            }
        }
    }

    pub fn run_encode<E>(&mut self, buffer: &mut [u8], data_length: u32)
    where
        E: Encode,
    {
        if self.scheme.version < (1, 2) || buffer.len() < 3 {
            return;
        }

        self.rng.seed(data_length);

        let a;
        let b;

        let mut index = 0usize;

        let mut effective_length = data_length.min(1024);
        let mut fac = 0u32;

        if self.scheme.version > (1, 2) {
            a = (buffer[0] ^ (data_length & 0xFF) as u8) as i8;
            b = (buffer[1] ^ ((data_length >> 1) & 0xFF) as u8) as i8;

            if data_length as usize != get_index_size(self.scheme.version)
                && (self.scheme.version > (1, 3) || self.scheme.scheme_version > 2150)
            {
                // regular entry encryption
                let idx = (self.rng.next_rand() as f64
                    * (self.scheme.shiina_image.len() as f64 / 4294967296.0))
                    as f64;
                if self.scheme.version >= (1, 6) {
                    fac = self.rng.0 + self.scheme.shiina_image[idx as usize] as u32;
                    fac = helper::decrypt_helper3(fac) & 0xfffffff;

                    if effective_length > 0x80 && self.scheme.scheme_version > 2350 {
                        helper::decrypt_helper4(
                            &mut buffer[index + 4..],
                            &self.scheme.helper_key,
                            &self.scheme.region,
                            self.scheme.scheme_version,
                        );
                        index += 0x80;
                        effective_length -= 0x80;
                    }
                } else {
                    todo!("WARC < 1.6 not suppported")
                }
            }
        } else {
            todo!("WARC 1.2 not suppported")
        }

        let buffer = &mut buffer[index..];

        self.rng
            .seed(self.rng.peek() ^ (helper::decrypt_helper1(a as f64) * 100000000.0) as u32);

        let mut token = 0f64;

        if 0 != (a | b) {
            let a = a as f64;
            let b = b as f64;

            token = (a / (a * a + b * b).sqrt()).acos();
            token = token / std::f64::consts::PI * 180.0;
        }

        if b < 0 {
            token = 360.0 - token;
        }

        let x = (fac + helper::decrypt_helper2(token, &mut self.rng) & 0xFF) as i32
            % self.scheme.key.len() as i32;

        E::encode(
            &mut buffer[index..effective_length as usize],
            self.scheme.version,
            &self.scheme.key,
            x as u32,
            &mut self.rng,
        );
    }

    pub fn decrypt_index(&mut self, index: &mut [u8], offset: u32) {
        self.run_encode::<Decrypter>(index, index.len() as u32);
        self.xor_index(index, offset);
    }
}

pub const ENTRY_NAME_SIZE: usize = 0x10;

pub fn get_index_size((major, minor): (u8, u8)) -> usize {
    let max_index_entries = if (major, minor) < (1, 5) /* || scheme < 2310 */ {
        8192
    } else {
        16384
    };

    (ENTRY_NAME_SIZE + 0x18) * max_index_entries
}
