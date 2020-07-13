// https://github.com/morkt/GARbro/blob/f8761f4a961330c6cba1bb0bf964d3249e7843a7/ArcFormats/ShiinaRio/WarcEncryption.cs

pub(super) fn decrypt_helper1(a: f64) -> f64 {
    if a < 0.0 {
        return -decrypt_helper1(-a);
    }

    let mut v0: f64;
    let mut v1: f64;

    if a < 18.0 {
        v0 = a;
        v1 = a;
        let v2 = -(a * a);

        let mut j = 3;
        loop {
            v1 *= v2 / (j * (j - 1)) as f64;
            v0 += v1 / j as f64;

            if v0 == v2 {
                break;
            }
            j += 2;

            if j >= 1000 {
                break;
            }
        }
        return v0;
    }

    let mut flags = 0i32;
    let mut v0_l = 0f64;
    v1 = 0.0;
    let mut div = 1.0 / a;
    let mut v1_h = 2.0;
    let mut v0_h = 2.0;
    let mut v1_l = 0f64;
    v0 = 0.0;
    let mut i = 0;

    loop {
        v0 += div;
        
        i += 1;
        div *= i as f64 / a;

        if v0 < v0_h {
            v0_h = v0;
        } else {
            flags |= 1;
        }

        v1 += div;
        
        i += 1;
        div *= i as f64 / a;

        if v1 < v1_h {
            v1_h = v1;
        } else {
            flags |= 2;
        }

        v0 -= div;
        
        i += 1;
        div *= i as f64 / a;

        if v0 > v0_l {
            v0_l = v0;
        } else {
            flags |= 4;
        }

        v1 -= div;
        
        i += 1;
        div *= i as f64 / a;

        if v1 > v1_l {
            v1_l = v1;
        } else {
            flags |= 8;
        }

        if flags == 0x0f {
            break;
        }
    }

    ((std::f64::consts::PI - a.cos() * (v0_l + v0_h)) - (a.sin() * (v1_l + v1_h))) / 2.0
}

use super::Rng;

pub(super) fn decrypt_helper2<R: Rng>(a: f64, rng: &mut R) -> u32 {
    let v0;
    let mut v1;
    let mut v2;
    let mut v3;

    if a > 1.0 {
        v0 = (a * 2.0 - 1.0).sqrt();

        loop {
            v1 = 1.0 - rng.next_rand() as f64 / 4294967296.0;
            v2 = 2.0 * rng.next_rand() as f64 / 4294967296.0 - 1.0;
            if v1 * v1 + v2 * v2 > 1.0 {
                continue;
            }

            v2 /= v1;
            v3 = v2 * v0 + a - 1.0;
            if v3 <= 0.0 {
                continue;
            }

            v1 = (a - 1.0) * (v3 / (a - 1.0)).ln() - v2 * v0;
            if v1 < -50.0 {
                continue;
            }

            if (rng.next_rand() as f64 / 4294967296.0) <= ((v1).exp() * (v2 * v2 + 1.0)) {
                break;
            }
        }
    } else {
        v0 = (1.0f64).exp() / (a + (1.0f64).exp());
        
        loop {
            v1 = rng.next_rand() as f64 / 4294967296.0;
            v2 = rng.next_rand() as f64 / 4294967296.0;

            if v1 < v0 {
                v3 = v2.powf(1.0 / a);
                v1 = (-v3).exp();
            } else {
                v3 = 1.0 - v2.ln();
                v1 = v3.powf(a - 1.0);
            }

            if rng.next_rand() as f64 / 4294967296.0 < v1 {
                break;
            }
        }
    }

    // WARC <= 1.2 not supported
    (v3 * 256.0) as u32
}

pub(super) fn decrypt_helper3(key: u32) -> u32 {
    let le = key.to_le_bytes();

    let v0 = (1.5 * le[0] as f64 + 0.1) as f32;
    let v0 = u32::from_be_bytes(v0.to_le_bytes());

    let v1 = (1.5 * le[1] as f64 + 0.1) as f32 as i32 as u32;

    let v2: i32 = unsafe { std::mem::transmute((1.5 * le[2] as f64 + 0.1) as f32) };
    let v2 = (-v2) as u32;
    
    let v3: i32 = unsafe { std::mem::transmute((1.5 * le[2] as f64 + 0.1) as f32) };
    let v3 = !(v3 as u32);

    (v0 + v1) | (v2 - v3)
}

pub(super) fn decrypt_helper4(
    data: &mut [u8],
    helper_key: &[u32],
    region: &[u8],
    scheme_version: u32,
) {
    use std::convert::TryInto;

    let mut buf = vec![0u32; 0x50];
    for i in 0..0x10 {
        let arr: [u8; 4] = data[40 + 4 * i..][..4].try_into().unwrap();
        buf[i] = u32::from_be_bytes(arr);
    }

    for i in 0x10..0x50 {
        let mut v = buf[i - 16];
        v ^= buf[i - 14];
        v ^= buf[i - 8];
        v ^= buf[i - 3];
        buf[i] = v.rotate_left(1);
    }

    let mut key = vec![0u32; 10];
    key[..5].copy_from_slice(&helper_key[..5]);

    let mut k0 = key[0];
    let mut k1 = key[1];
    let mut k2 = key[2];
    let mut k3 = key[3];
    let mut k4 = key[4];

    use std::num::Wrapping;

    for (i, &x) in buf.iter().enumerate() {
        let (f, c) = if i < 0x10 {
            (k1 ^ k2 ^ k3, 0)
        } else if i < 0x20 {
            (k1 & k2 | k3 & !k1, 0x5A827999u32)
        } else if i < 0x30 {
            (k3 ^ (k1 | !k2), 0x6ED9EBA1)
        } else if i < 0x40 {
            (k1 & k3 | k2 & !k3, 0x8F1BBCDC)
        } else {
            (k1 ^ (k2 | !k3), 0xA953FD4E)
        };

        let new_k0 =
            Wrapping(x) + Wrapping(k4) + Wrapping(f) + Wrapping(c) + Wrapping(k0.rotate_left(5));
        let new_k0 = new_k0.0;
        let new_k2 = k1.rotate_right(2);

        k1 = k0;
        k4 = k3;
        k3 = k2;
        k2 = new_k2;
        k0 = new_k0;
    }

    key[0] = key[0].wrapping_add(k0);
    key[1] = key[1].wrapping_add(k1);
    key[2] = key[2].wrapping_add(k2);
    key[3] = key[3].wrapping_add(k3);
    key[4] = key[4].wrapping_add(k4);

    use chrono::prelude::*;

    let filetime = key[1] as u64 | (((key[0] & 0x7FFFFFFF) as u64) << 32);
    let epoch_time = Utc.ymd(1601, 1, 1).and_hms(0, 0, 0);
    let time = epoch_time + chrono::Duration::nanoseconds(filetime as i64);

    key[5] = time.year() as u32 | (time.month() << 16);
    key[7] = time.hour() | (time.minute() << 16);
    key[8] = time.second() | ((time.nanosecond() / 1000) << 16);

    let flag_bytes: [u8; 4] = data[40..][..4].try_into().unwrap();
    let mut flags = u32::from_be_bytes(flag_bytes);

    let rgb = buf[1] >> 8;
    if 0 == (flags & 0x78000000) {
        flags |= 0x98000000;
    }

    key[6] = region_crc_32(region, flags, rgb);
    key[9] = ((key[2] as u64 * key[3] as u64) >> 8) as u32;

    if scheme_version >= 2390 {
        key[6] += key[9];
    }

    for i in 0..10 {
        let j = i * 4;
        let arr: [u8; 4] = data[j..][..4].try_into().unwrap();
        let newval = u32::from_le_bytes(arr) ^ key[i];
        let newval = newval.to_le_bytes();
        data[j..][..4].copy_from_slice(&newval);
    }
}

fn region_crc_32(src: &[u8], flags: u32, rgb: u32) -> u32 {
    let mut src_alpha = flags as i32 & 0x1ff;
    let mut dst_alpha = (flags as i32 >> 12) & 0x1ff;

    let flags = flags >> 24;
    if 0 == (flags & 0x10) {
        dst_alpha = 0;
    }
    if 0 == (flags & 8) {
        src_alpha = 0x100;
    }

    let mut x_step = 4i32;
    let mut y_step = 0i32;
    let width = 48;
    let mut pos = 0;

    // h-flip
    if 0 != flags & 0x40 {
        y_step += width;
        pos += (width - 1) * 4;
        x_step = -x_step;
    }

    // v-flip
    if 0 != (flags & 0x20) {
        y_step -= width;
        pos += width * 0x2f * 4;
    }

    y_step <<= 3;
    let mut checksum = 0u32;

    for _ in 0..48 {
        for _ in 0..48 {
            let alpha = (src[(pos + 3) as usize] as i32 * src_alpha) >> 8;
            let mut color = rgb;
            for i in 0..3 {
                let v = src[(pos + i) as usize] as i32;
                let mut c = (color & 0xff) as i32;
                c -= v;
                c = (c * dst_alpha as i32) >> 8;
                c = (c + v) & 0xff;
                c = (c * alpha) >> 8;
                checksum =
                    (checksum >> 8) ^ CRC_TABLE[((c as u32 ^ checksum) & 0xff) as usize] as u32;
                color >>= 8;
            }
            pos += x_step;
        }
        pos += y_step;
    }

    checksum
}

use lazy_static::*;

lazy_static! {
    static ref CRC_TABLE: Vec<u32> = {
        let mut table = vec![0u32; 0x100];

        for i in 0u32..0x100 {
            let mut poly = i;

            for _ in 0..8 {
                let bit = poly & 1;
                poly = poly.rotate_right(1);

                if bit == 0 {
                    poly ^= 0x6DB88320;
                }
            }

            table[i as usize] = poly;
        }

        table
    };
}
