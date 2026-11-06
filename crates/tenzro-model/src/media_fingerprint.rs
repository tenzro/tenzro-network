//! Perceptual fingerprints of generated media.
//!
//! A diffusion render is seeded, so the same model, parameters and seed give
//! the same picture, clip or track on any machine, up to the numeric drift of
//! the hardware and kernels it ran on: never bit for bit across devices, but
//! never far. A fingerprint keeps what that drift leaves alone and a
//! different render changes, small enough to commit to in a receipt:
//!
//! - pictures and video frames: the mean luma (BT.601) of each cell of a
//!   [`LUMA_GRID`] x [`LUMA_GRID`] grid, for every frame of a still and up to
//!   [`MAX_FRAMES`] evenly spaced frames of a clip;
//! - sound: the RMS level of each [`ENVELOPE_WINDOW_MS`] window;
//! - a 3D asset (binary glTF): the share of its surface area in each cell of
//!   a [`GEOMETRY_GRID`]^3 grid over the cube that bounds its mesh. A device
//!   that simplifies the surface to other triangles moves little area
//!   between cells; another shape moves much.
//!
//! Two fingerprints [`agree`] when every part has the same shape and lies
//! within a relative L2 distance of the other. Integer arithmetic for pixels
//! and sound, IEEE arithmetic in a fixed order for geometry, so every party
//! computes the same fingerprint from the same bytes.

use serde::{Deserialize, Serialize};

/// Cells on each side of a frame's luma grid.
pub const LUMA_GRID: usize = 16;
/// Frames of a clip that are fingerprinted.
pub const MAX_FRAMES: usize = 8;
/// Length of one envelope window.
pub const ENVELOPE_WINDOW_MS: u32 = 100;
/// Cells on each side of a 3D asset's area grid.
pub const GEOMETRY_GRID: usize = 8;
/// Area shares are counted in units of `1 / GEOMETRY_SCALE` of the surface.
pub const GEOMETRY_SCALE: f64 = 65_535.0;

/// The tolerance a picture or clip is held to, in basis points of relative
/// L2 distance.
pub const VISUAL_TOLERANCE_BPS: u32 = 500;
/// The tolerance sound is held to.
pub const AUDIO_TOLERANCE_BPS: u32 = 1000;
/// The tolerance a 3D asset is held to.
pub const GEOMETRY_TOLERANCE_BPS: u32 = 1000;
/// The largest tolerance a fingerprint comparison accepts.
pub const MAX_TOLERANCE_BPS: u32 = 1000;

/// What a render looks and sounds like, coarsely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaFingerprint {
    /// `frames x LUMA_GRID x LUMA_GRID` cell means, frame-major, row-major.
    pub luma: Vec<u8>,
    /// RMS sample level of each envelope window.
    pub envelope: Vec<u16>,
    /// Surface area share of each cell of a 3D asset's grid, x-major then y
    /// then z.
    pub geometry: Vec<u16>,
}

impl MediaFingerprint {
    /// The tolerance this kind of output is held to.
    #[must_use]
    pub fn tolerance_bps(&self) -> u32 {
        if !self.geometry.is_empty() {
            GEOMETRY_TOLERANCE_BPS
        } else if self.luma.is_empty() {
            AUDIO_TOLERANCE_BPS
        } else {
            VISUAL_TOLERANCE_BPS
        }
    }
}

/// The fingerprint of an encoded output, by its media type: `image/png`,
/// `audio/wav`, `video/x-yuv4mpeg2`, `video/x-msvideo` (uncompressed RGB
/// frames with optional 16-bit PCM) or `model/gltf-binary` (triangle meshes
/// with float positions). `None` for any other type, or bytes that do not
/// parse as theirs.
#[must_use]
pub fn of(mime: &str, bytes: &[u8]) -> Option<MediaFingerprint> {
    match mime {
        "image/png" => {
            let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
                .ok()?
                .to_rgb8();
            let (w, h) = (img.width() as usize, img.height() as usize);
            Some(MediaFingerprint {
                luma: luma_grid(w, h, |x, y| rgb_luma(&img.as_raw()[(y * w + x) * 3..])),
                envelope: Vec::new(),
                geometry: Vec::new(),
            })
        }
        "audio/wav" => {
            let (rate, channels, pcm) = wav_pcm16(bytes)?;
            Some(MediaFingerprint {
                luma: Vec::new(),
                envelope: envelope(rate, channels, pcm),
                geometry: Vec::new(),
            })
        }
        "video/x-yuv4mpeg2" => y4m(bytes),
        "video/x-msvideo" => avi(bytes),
        #[cfg(feature = "engine")]
        "video/mp4" => mp4(bytes),
        "model/gltf-binary" => Some(MediaFingerprint {
            luma: Vec::new(),
            envelope: Vec::new(),
            geometry: area_grid(&glb_triangles(bytes)?)?,
        }),
        _ => None,
    }
}

/// Whether two fingerprints are of the same render within `tolerance_bps`
/// (capped at [`MAX_TOLERANCE_BPS`]): each part the same length, and each
/// part's L2 distance at most that share of the larger part's norm, with a
/// floor of one unit per element.
#[must_use]
pub fn agree(a: &MediaFingerprint, b: &MediaFingerprint, tolerance_bps: u32) -> bool {
    let tol = f64::from(tolerance_bps.min(MAX_TOLERANCE_BPS)) / 10_000.0;
    let close = |x: &[f64], y: &[f64]| -> bool {
        if x.len() != y.len() {
            return false;
        }
        let norm = |v: &[f64]| v.iter().map(|e| e * e).sum::<f64>().sqrt();
        let diff = x
            .iter()
            .zip(y)
            .map(|(p, q)| (p - q) * (p - q))
            .sum::<f64>()
            .sqrt();
        diff <= tol * norm(x).max(norm(y)) + (x.len() as f64).sqrt()
    };
    let wide = |v: &[u8]| v.iter().map(|&e| f64::from(e)).collect::<Vec<_>>();
    let wide16 = |v: &[u16]| v.iter().map(|&e| f64::from(e)).collect::<Vec<_>>();
    close(&wide(&a.luma), &wide(&b.luma))
        && close(&wide16(&a.envelope), &wide16(&b.envelope))
        && close(&wide16(&a.geometry), &wide16(&b.geometry))
}

fn rgb_luma(px: &[u8]) -> u32 {
    (299 * u32::from(px[0]) + 587 * u32::from(px[1]) + 114 * u32::from(px[2]) + 500) / 1000
}

/// Cell means of a `w` x `h` frame whose luma at `(x, y)` (top-left origin)
/// is `at(x, y)`. A frame narrower than the grid repeats its pixels.
fn luma_grid(w: usize, h: usize, at: impl Fn(usize, usize) -> u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(LUMA_GRID * LUMA_GRID);
    if w == 0 || h == 0 {
        return vec![0; LUMA_GRID * LUMA_GRID];
    }
    let span = |i: usize, n: usize| {
        let a = (i * n / LUMA_GRID).min(n - 1);
        (a, ((i + 1) * n / LUMA_GRID).max(a + 1).min(n))
    };
    for gy in 0..LUMA_GRID {
        let (y0, y1) = span(gy, h);
        for gx in 0..LUMA_GRID {
            let (x0, x1) = span(gx, w);
            let mut sum = 0u64;
            for y in y0..y1 {
                for x in x0..x1 {
                    sum += u64::from(at(x, y));
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u64;
            out.push(((sum + n / 2) / n) as u8);
        }
    }
    out
}

/// Indices of the frames fingerprinted out of `n`.
fn picked(n: usize) -> Vec<usize> {
    let k = n.min(MAX_FRAMES);
    match k {
        0 => Vec::new(),
        1 => vec![0],
        _ => (0..k).map(|i| i * (n - 1) / (k - 1)).collect(),
    }
}

fn envelope(rate: u32, channels: u16, pcm: &[u8]) -> Vec<u16> {
    let window =
        ((rate as usize * ENVELOPE_WINDOW_MS as usize) / 1000).max(1) * channels.max(1) as usize;
    let samples: Vec<i16> = pcm
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b))
        .collect();
    samples
        .chunks(window)
        .map(|w| {
            let sum: u64 = w
                .iter()
                .map(|&x| (i64::from(x) * i64::from(x)) as u64)
                .sum();
            (sum / w.len() as u64).isqrt() as u16
        })
        .collect()
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Sample rate, channel count and PCM bytes of a 16-bit PCM WAV.
fn wav_pcm16(wav: &[u8]) -> Option<(u32, u16, &[u8])> {
    if wav.get(0..4)? != b"RIFF" || wav.get(8..12)? != b"WAVE" {
        return None;
    }
    let mut at = 12;
    let mut format = None;
    while at + 8 <= wav.len() {
        let len = u32_at(wav, at + 4)? as usize;
        let body = wav.get(at + 8..(at + 8).checked_add(len)?.min(wav.len()))?;
        match &wav[at..at + 4] {
            b"fmt " if body.len() >= 16 => {
                let (tag, channels, rate, bits) = (
                    u16_at(body, 0)?,
                    u16_at(body, 2)?,
                    u32_at(body, 4)?,
                    u16_at(body, 14)?,
                );
                if tag != 1 || bits != 16 || channels == 0 || rate == 0 {
                    return None;
                }
                format = Some((rate, channels));
            }
            b"data" => {
                let (rate, channels) = format?;
                return Some((rate, channels, body));
            }
            _ => {}
        }
        at += 8 + len + (len & 1);
    }
    None
}

/// A YUV4MPEG2 stream: the luma plane of each picked frame.
fn y4m(bytes: &[u8]) -> Option<MediaFingerprint> {
    let header_end = bytes.iter().position(|&b| b == b'\n')?;
    let header = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut tokens = header.split(' ');
    if tokens.next()? != "YUV4MPEG2" {
        return None;
    }
    let (mut w, mut h, mut chroma) = (0usize, 0usize, "420");
    for t in tokens {
        match t.split_at_checked(1)? {
            ("W", v) => w = v.parse().ok()?,
            ("H", v) => h = v.parse().ok()?,
            ("C", v) => chroma = v,
            _ => {}
        }
    }
    let plane = w.checked_mul(h)?;
    let frame = match chroma.get(..3)? {
        "444" => plane * 3,
        "422" => plane * 2,
        "420" => plane + 2 * w.div_ceil(2) * h.div_ceil(2),
        "mon" => plane,
        _ => return None,
    };
    let mut planes = Vec::new();
    let mut at = header_end + 1;
    while at < bytes.len() {
        let line_end = at + bytes[at..].iter().position(|&b| b == b'\n')?;
        if !bytes[at..line_end].starts_with(b"FRAME") {
            return None;
        }
        let start = line_end + 1;
        planes.push(&bytes.get(start..start + frame)?[..plane]);
        at = start + frame;
    }
    let mut luma = Vec::new();
    for i in picked(planes.len()) {
        let p = planes[i];
        luma.extend(luma_grid(w, h, |x, y| u32::from(p[y * w + x])));
    }
    (!luma.is_empty()).then_some(MediaFingerprint {
        luma,
        envelope: Vec::new(),
        geometry: Vec::new(),
    })
}

/// An MP4 (H.264, H.265 or AV1): the luma of each picked decoded frame.
/// The sound track, if any, is not part of the fingerprint.
#[cfg(feature = "engine")]
fn mp4(bytes: &[u8]) -> Option<MediaFingerprint> {
    let (frames, _) = praecise_diffusion::frames_from_video(bytes).ok()?;
    let mut luma = Vec::new();
    for i in picked(frames.len()) {
        let f = &frames[i];
        let (w, h) = (f.width as usize, f.height as usize);
        if f.rgb.len() < w * h * 3 {
            return None;
        }
        luma.extend(luma_grid(w, h, |x, y| rgb_luma(&f.rgb[(y * w + x) * 3..])));
    }
    (!luma.is_empty()).then_some(MediaFingerprint {
        luma,
        envelope: Vec::new(),
        geometry: Vec::new(),
    })
}

/// An uncompressed AVI: the luma of each picked 24-bit BGR frame and the
/// envelope of its 16-bit PCM sound, if it has any.
fn avi(bytes: &[u8]) -> Option<MediaFingerprint> {
    if bytes.get(0..4)? != b"RIFF" || bytes.get(8..12)? != b"AVI " {
        return None;
    }
    let mut formats = Vec::new();
    let mut frames = Vec::new();
    let mut pcm = Vec::new();
    walk(bytes, 12, bytes.len(), &mut |id, body| match id {
        b"strf" => formats.push(body),
        b"00dc" | b"00db" => frames.push(body),
        b"01wb" => pcm.extend_from_slice(body),
        _ => {}
    })?;
    let bih = formats.first()?;
    let (w, height, bits, compression) = (
        u32_at(bih, 4)? as usize,
        u32_at(bih, 8)? as i32,
        u16_at(bih, 14)?,
        u32_at(bih, 16)?,
    );
    if bits != 24 || compression != 0 || w == 0 || height == 0 {
        return None;
    }
    let h = height.unsigned_abs() as usize;
    let stride = (w * 3 + 3) & !3;
    let mut luma = Vec::new();
    for i in picked(frames.len()) {
        let f = frames[i];
        if f.len() < stride * h {
            return None;
        }
        luma.extend(luma_grid(w, h, |x, y| {
            let row = if height > 0 { h - 1 - y } else { y };
            let p = &f[row * stride + x * 3..];
            rgb_luma(&[p[2], p[1], p[0]])
        }));
    }
    let envelope = match formats.get(1) {
        Some(wfx) if !pcm.is_empty() && u16_at(wfx, 0)? == 1 && u16_at(wfx, 14)? == 16 => {
            envelope(u32_at(wfx, 4)?, u16_at(wfx, 2)?, &pcm)
        }
        _ => Vec::new(),
    };
    (!luma.is_empty()).then_some(MediaFingerprint {
        luma,
        envelope,
        geometry: Vec::new(),
    })
}

/// Visit every chunk of the RIFF tree in `b[at..end]`, descending into
/// `LIST` chunks.
fn walk<'a>(
    b: &'a [u8],
    mut at: usize,
    end: usize,
    visit: &mut impl FnMut(&[u8; 4], &'a [u8]),
) -> Option<()> {
    while at + 8 <= end {
        let id: &[u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        let len = u32_at(b, at + 4)? as usize;
        let body_end = (at + 8).checked_add(len)?.min(end);
        if id == b"LIST" {
            walk(b, at + 12, body_end, visit)?;
        } else {
            visit(id, b.get(at + 8..body_end)?);
        }
        at = at + 8 + len + (len & 1);
    }
    Some(())
}

/// The triangles of every triangle-list primitive of a binary glTF 2.0
/// asset, in mesh coordinates: float `POSITION`s, indexed or not, from the
/// asset's own binary chunk. `None` for anything else.
fn glb_triangles(bytes: &[u8]) -> Option<Vec<[[f32; 3]; 3]>> {
    if bytes.get(0..4)? != b"glTF" || u32_at(bytes, 4)? != 2 {
        return None;
    }
    let total = (u32_at(bytes, 8)? as usize).min(bytes.len());
    let (mut json, mut bin) = (None, None);
    let mut at = 12;
    while at + 8 <= total {
        let len = u32_at(bytes, at)? as usize;
        let body = bytes.get(at + 8..(at + 8).checked_add(len)?)?;
        match u32_at(bytes, at + 4)? {
            0x4E4F_534A => json = Some(body),
            0x004E_4942 => bin = Some(body),
            _ => {}
        }
        at += 8 + len;
    }
    let doc: serde_json::Value = serde_json::from_slice(json?).ok()?;
    let bin = bin?;
    let get = |v: &serde_json::Value, k: &str| v.get(k).and_then(serde_json::Value::as_u64);
    // One accessor's elements as rows of `n` values read by `read`.
    let rows =
        |index: u64, n: usize, size: usize, read: &dyn Fn(&[u8]) -> f64| -> Option<Vec<f64>> {
            let acc = doc.get("accessors")?.get(index as usize)?;
            let view = doc
                .get("bufferViews")?
                .get(get(acc, "bufferView")? as usize)?;
            if get(view, "buffer").unwrap_or(0) != 0 {
                return None;
            }
            let count = get(acc, "count")? as usize;
            let stride = get(view, "byteStride").map_or(n * size, |s| s as usize);
            let start = get(view, "byteOffset").unwrap_or(0) as usize
                + get(acc, "byteOffset").unwrap_or(0) as usize;
            let mut out = Vec::with_capacity(count * n);
            for i in 0..count {
                for j in 0..n {
                    let o = start + i * stride + j * size;
                    out.push(read(bin.get(o..o + size)?));
                }
            }
            Some(out)
        };
    let mut tris = Vec::new();
    for mesh in doc.get("meshes")?.as_array()? {
        for prim in mesh.get("primitives")?.as_array()? {
            if get(prim, "mode").unwrap_or(4) != 4 {
                continue;
            }
            let pos_acc = get(prim.get("attributes")?, "POSITION")?;
            let acc = doc.get("accessors")?.get(pos_acc as usize)?;
            if get(acc, "componentType")? != 5126 || acc.get("type")?.as_str()? != "VEC3" {
                return None;
            }
            let pos = rows(pos_acc, 3, 4, &|b| {
                f64::from(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            })?;
            let vertex = |i: usize| -> Option<[f32; 3]> {
                Some([
                    *pos.get(3 * i)? as f32,
                    *pos.get(3 * i + 1)? as f32,
                    *pos.get(3 * i + 2)? as f32,
                ])
            };
            let indices: Vec<usize> = match get(prim, "indices") {
                Some(ix) => {
                    let acc = doc.get("accessors")?.get(ix as usize)?;
                    let (size, read): (usize, &dyn Fn(&[u8]) -> f64) =
                        match get(acc, "componentType")? {
                            5121 => (1, &|b| f64::from(b[0])),
                            5123 => (2, &|b| f64::from(u16::from_le_bytes([b[0], b[1]]))),
                            5125 => (4, &|b| {
                                f64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                            }),
                            _ => return None,
                        };
                    rows(ix, 1, size, read)?
                        .into_iter()
                        .map(|v| v as usize)
                        .collect()
                }
                None => (0..pos.len() / 3).collect(),
            };
            for t in indices.as_chunks::<3>().0 {
                tris.push([vertex(t[0])?, vertex(t[1])?, vertex(t[2])?]);
            }
        }
    }
    Some(tris)
}

/// Each [`GEOMETRY_GRID`]^3 cell's share of the total surface area, in units
/// of `1 / GEOMETRY_SCALE`: a triangle counts in the cell holding its
/// centroid, and the grid spans the cube centred on the mesh's bounding box
/// whose side is the box's longest. `None` for a mesh with no area.
fn area_grid(tris: &[[[f32; 3]; 3]]) -> Option<Vec<u16>> {
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for v in tris.iter().flatten() {
        for k in 0..3 {
            let x = f64::from(v[k]);
            if !x.is_finite() {
                return None;
            }
            lo[k] = lo[k].min(x);
            hi[k] = hi[k].max(x);
        }
    }
    let side = (0..3).map(|k| hi[k] - lo[k]).fold(0.0, f64::max);
    if side <= 0.0 {
        return None;
    }
    let g = GEOMETRY_GRID;
    let mut area = vec![0.0f64; g * g * g];
    let mut total = 0.0;
    for t in tris {
        let p = t.map(|v| v.map(f64::from));
        let (u, w) = (
            [0, 1, 2].map(|k| p[1][k] - p[0][k]),
            [0, 1, 2].map(|k| p[2][k] - p[0][k]),
        );
        let c = [
            u[1] * w[2] - u[2] * w[1],
            u[2] * w[0] - u[0] * w[2],
            u[0] * w[1] - u[1] * w[0],
        ];
        let a = 0.5 * (c[0] * c[0] + c[1] * c[1] + c[2] * c[2]).sqrt();
        let cell = [0, 1, 2].map(|k| {
            let start = (lo[k] + hi[k] - side) / 2.0;
            let x = (p[0][k] + p[1][k] + p[2][k]) / 3.0;
            (((x - start) / side * g as f64) as usize).min(g - 1)
        });
        area[(cell[0] * g + cell[1]) * g + cell[2]] += a;
        total += a;
    }
    if total <= 0.0 {
        return None;
    }
    Some(
        area.iter()
            .map(|a| (a / total * GEOMETRY_SCALE).round() as u16)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32, f: impl Fn(u32, u32) -> [u8; 3]) -> Vec<u8> {
        let mut img = image::RgbImage::new(w, h);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb(f(x, y));
        }
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    fn wav(rate: u32, samples: &[i16]) -> Vec<u8> {
        let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 2).to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(data.len() as u32).to_le_bytes());
        w.extend_from_slice(&data);
        w
    }

    /// A smooth picture, the same picture with a little per-pixel noise (the
    /// drift of another device), and a different picture.
    #[test]
    fn a_picture_agrees_with_its_drifted_render_and_not_with_another() {
        let base = |x: u32, y: u32| [(x * 2) as u8, (y * 3) as u8, ((x + y) % 256) as u8];
        let a = of("image/png", &png(80, 64, base)).unwrap();
        let drift = of(
            "image/png",
            &png(80, 64, |x, y| {
                let [r, g, b] = base(x, y);
                let d = ((x * 7 + y * 13) % 5) as u8;
                [r.saturating_add(d), g.saturating_sub(d / 2), b]
            }),
        )
        .unwrap();
        let other = of(
            "image/png",
            &png(80, 64, |x, y| [(255 - x * 2) as u8, (y * 3) as u8, 40]),
        )
        .unwrap();
        assert_eq!(a.luma.len(), LUMA_GRID * LUMA_GRID);
        assert_eq!(a.tolerance_bps(), VISUAL_TOLERANCE_BPS);
        assert!(agree(&a, &drift, a.tolerance_bps()));
        assert!(!agree(&a, &other, a.tolerance_bps()));
        // A tolerance above the cap is held to the cap.
        assert_eq!(
            agree(&a, &other, u32::MAX),
            agree(&a, &other, MAX_TOLERANCE_BPS)
        );
    }

    /// A binary glTF of one indexed triangle list.
    fn glb(positions: &[[f32; 3]], indices: &[u32]) -> Vec<u8> {
        let mut bin: Vec<u8> = positions
            .iter()
            .flatten()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let pos_len = bin.len();
        bin.extend(indices.iter().flat_map(|i| i.to_le_bytes()));
        let json = serde_json::json!({
            "asset": { "version": "2.0" },
            "buffers": [{ "byteLength": bin.len() }],
            "bufferViews": [
                { "buffer": 0, "byteOffset": 0, "byteLength": pos_len },
                { "buffer": 0, "byteOffset": pos_len, "byteLength": bin.len() - pos_len },
            ],
            "accessors": [
                { "bufferView": 0, "componentType": 5126, "count": positions.len(), "type": "VEC3" },
                { "bufferView": 1, "componentType": 5125, "count": indices.len(), "type": "SCALAR" },
            ],
            "meshes": [{ "primitives": [{ "attributes": { "POSITION": 0 }, "indices": 1 }] }],
        });
        let mut json = serde_json::to_vec(&json).unwrap();
        while !json.len().is_multiple_of(4) {
            json.push(b' ');
        }
        let mut out = b"glTF".to_vec();
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&((12 + 8 + json.len() + 8 + bin.len()) as u32).to_le_bytes());
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(b"JSON");
        out.extend(json);
        out.extend_from_slice(&(bin.len() as u32).to_le_bytes());
        out.extend_from_slice(b"BIN\0");
        out.extend(bin);
        out
    }

    /// A unit sphere of `n` x `n` latitude-longitude quads, its vertices moved
    /// by `wobble(i)`, stretched by `stretch` along x.
    fn sphere(n: usize, stretch: f32, wobble: impl Fn(usize) -> f32) -> Vec<u8> {
        let mut pos = Vec::new();
        for i in 0..=n {
            for j in 0..=n {
                let (th, ph) = (
                    std::f32::consts::PI * i as f32 / n as f32,
                    2.0 * std::f32::consts::PI * j as f32 / n as f32,
                );
                let r = 1.0 + wobble(pos.len());
                pos.push([
                    r * th.sin() * ph.cos() * stretch,
                    r * th.cos(),
                    r * th.sin() * ph.sin(),
                ]);
            }
        }
        let mut idx = Vec::new();
        for i in 0..n as u32 {
            for j in 0..n as u32 {
                let (a, b) = (i * (n as u32 + 1) + j, (i + 1) * (n as u32 + 1) + j);
                idx.extend_from_slice(&[a, b, a + 1, a + 1, b, b + 1]);
            }
        }
        glb(&pos, &idx)
    }

    #[test]
    fn a_mesh_agrees_with_its_drifted_render_and_not_with_another_shape() {
        let a = of("model/gltf-binary", &sphere(160, 1.0, |_| 0.0)).unwrap();
        // Another device: slightly moved vertices, and a different tessellation.
        let drift = of(
            "model/gltf-binary",
            &sphere(160, 1.0, |i| ((i * 7919) % 13) as f32 * 1e-3),
        )
        .unwrap();
        let coarser = of("model/gltf-binary", &sphere(128, 1.0, |_| 0.0)).unwrap();
        let stretched = of("model/gltf-binary", &sphere(160, 2.0, |_| 0.0)).unwrap();
        assert_eq!(a.geometry.len(), GEOMETRY_GRID.pow(3));
        assert!(a.luma.is_empty() && a.envelope.is_empty());
        assert_eq!(a.tolerance_bps(), GEOMETRY_TOLERANCE_BPS);
        let sum: u32 = a.geometry.iter().map(|&v| u32::from(v)).sum();
        assert!(
            sum.abs_diff(GEOMETRY_SCALE as u32) < 300,
            "shares sum to the whole surface: {sum}"
        );
        assert!(agree(&a, &drift, a.tolerance_bps()));
        assert!(agree(&a, &coarser, a.tolerance_bps()));
        assert!(!agree(&a, &stretched, a.tolerance_bps()));
        // A picture is never the same output as a mesh.
        let picture = MediaFingerprint {
            luma: vec![0; 4],
            envelope: Vec::new(),
            geometry: Vec::new(),
        };
        assert!(!agree(&a, &picture, MAX_TOLERANCE_BPS));
        // Not a GLB, or a GLB with no surface.
        assert!(of("model/gltf-binary", b"glTF").is_none());
        assert!(of("model/gltf-binary", &glb(&[[0.0; 3]; 3], &[0, 1, 2])).is_none());
    }

    #[test]
    fn sound_agrees_by_its_envelope() {
        let tone = |amp: f32, len: usize| -> Vec<i16> {
            (0..len)
                .map(|i| {
                    ((i as f32 * 0.3).sin() * amp * if i < len / 2 { 1.0 } else { 0.2 }) as i16
                })
                .collect()
        };
        let a = of("audio/wav", &wav(8000, &tone(8000.0, 16000))).unwrap();
        let louder = of("audio/wav", &wav(8000, &tone(8100.0, 16000))).unwrap();
        let quiet_early: Vec<i16> = tone(8000.0, 16000)
            .iter()
            .enumerate()
            .map(|(i, &s)| if i > 2400 { s / 20 } else { s })
            .collect();
        let short = of("audio/wav", &wav(8000, &quiet_early)).unwrap();
        assert_eq!(a.envelope.len(), 20, "100 ms windows over 2 s");
        assert!(agree(&a, &louder, a.tolerance_bps()));
        assert!(!agree(&a, &short, a.tolerance_bps()));
        // A different length is a different render.
        let cut = of("audio/wav", &wav(8000, &tone(8000.0, 12000))).unwrap();
        assert!(!agree(&a, &cut, AUDIO_TOLERANCE_BPS));
    }

    #[test]
    fn video_streams_are_fingerprinted_on_their_frames() {
        // Ten 32x16 frames of YUV 4:4:4 whose luma ramps with the frame.
        let (w, h) = (32usize, 16usize);
        let mut y4m_bytes = format!("YUV4MPEG2 W{w} H{h} F25:1 Ip A1:1 C444\n").into_bytes();
        for f in 0..10u8 {
            y4m_bytes.extend_from_slice(b"FRAME\n");
            y4m_bytes.extend(std::iter::repeat_n(f * 20, w * h));
            y4m_bytes.extend(std::iter::repeat_n(128u8, 2 * w * h));
        }
        let v = of("video/x-yuv4mpeg2", &y4m_bytes).unwrap();
        assert_eq!(v.luma.len(), MAX_FRAMES * LUMA_GRID * LUMA_GRID);
        assert_eq!(v.luma[0], 0);
        assert_eq!(
            *v.luma.last().unwrap(),
            180,
            "the last picked frame is the last frame"
        );
        assert!(
            of("video/x-yuv4mpeg2", &y4m_bytes[..y4m_bytes.len() - 7]).is_none(),
            "a truncated frame"
        );
        assert!(of("application/json", b"{}").is_none());
    }

    /// The engine's own MP4 encoding of a clip fingerprints like its frames,
    /// and a different clip does not.
    #[cfg(feature = "engine")]
    #[test]
    fn an_mp4_fingerprints_its_decoded_frames() {
        let (w, h, n) = (64u32, 48u32, 9u32);
        let clip = |shade: fn(u32, u32, u32) -> u8| {
            let mut rgb = Vec::with_capacity((w * h * n * 3) as usize);
            for f in 0..n {
                for y in 0..h {
                    for x in 0..w {
                        let v = shade(f, x, y);
                        rgb.extend_from_slice(&[v, v, v]);
                    }
                }
            }
            praecise_diffusion::Video {
                width: w,
                height: h,
                frames: n,
                fps: 8.0,
                rgb,
                seed: 0,
                evaluations: 0,
                timings: Default::default(),
            }
        };
        let ramp = clip(|f, x, _| (x * 3 + f * 4) as u8);
        let bytes = ramp.mp4(None).expect("the engine encodes the clip");
        let fp = of("video/mp4", &bytes).expect("an mp4 has a fingerprint");
        let raw = MediaFingerprint {
            luma: picked(n as usize)
                .into_iter()
                .flat_map(|i| {
                    let frame = &ramp.rgb[i * (w * h * 3) as usize..];
                    luma_grid(w as usize, h as usize, |x, y| {
                        rgb_luma(&frame[(y * w as usize + x) * 3..])
                    })
                })
                .collect(),
            envelope: Vec::new(),
            geometry: Vec::new(),
        };
        assert!(
            agree(&fp, &raw, fp.tolerance_bps()),
            "decoded frames match their source"
        );
        let other = clip(|_, _, y| (255 - y * 5) as u8).mp4(None).unwrap();
        let other = of("video/mp4", &other).unwrap();
        assert!(
            !agree(&fp, &other, fp.tolerance_bps()),
            "a different clip differs"
        );
    }

    #[test]
    fn an_avi_reads_its_bottom_up_frames_and_its_sound() {
        // One 4x2 frame: top row white, bottom row black, stored bottom-up as
        // BGR with rows padded to 4 bytes; then 0.2 s of 1 kHz-rate sound.
        let (w, h) = (4u32, 2u32);
        let stride = 12usize;
        let mut frame = vec![0u8; stride * h as usize];
        frame[stride..stride + 12].fill(255);
        let le = |v: u32| v.to_le_bytes();
        let chunk = |id: &[u8], body: &[u8]| -> Vec<u8> {
            let mut c = id.to_vec();
            c.extend_from_slice(&le(body.len() as u32));
            c.extend_from_slice(body);
            if body.len() % 2 == 1 {
                c.push(0);
            }
            c
        };
        let list = |kind: &[u8], body: &[u8]| -> Vec<u8> {
            let mut inner = kind.to_vec();
            inner.extend_from_slice(body);
            chunk(b"LIST", &inner)
        };
        let mut bih = Vec::new();
        for v in [40, w, h] {
            bih.extend_from_slice(&le(v));
        }
        bih.extend_from_slice(&1u16.to_le_bytes());
        bih.extend_from_slice(&24u16.to_le_bytes());
        bih.extend_from_slice(&[0; 24]);
        let mut wfx = Vec::new();
        wfx.extend_from_slice(&1u16.to_le_bytes());
        wfx.extend_from_slice(&1u16.to_le_bytes());
        wfx.extend_from_slice(&le(1000));
        wfx.extend_from_slice(&le(2000));
        wfx.extend_from_slice(&2u16.to_le_bytes());
        wfx.extend_from_slice(&16u16.to_le_bytes());
        let pcm: Vec<u8> = (0..200).flat_map(|_| 1000i16.to_le_bytes()).collect();
        let mut hdrl = list(b"strl", &chunk(b"strf", &bih));
        hdrl.extend(list(b"strl", &chunk(b"strf", &wfx)));
        let mut movi = chunk(b"00dc", &frame);
        movi.extend(chunk(b"01wb", &pcm));
        let mut body = b"AVI ".to_vec();
        body.extend(list(b"hdrl", &hdrl));
        body.extend(list(b"movi", &movi));
        let avi_bytes = chunk(b"RIFF", &body);

        let v = of("video/x-msvideo", &avi_bytes).unwrap();
        assert_eq!(v.luma[0], 255, "the top-left cell is the white top row");
        assert_eq!(
            v.luma[LUMA_GRID * LUMA_GRID - 1],
            0,
            "the bottom-right cell is black"
        );
        assert_eq!(v.envelope, vec![1000, 1000]);
    }
}
