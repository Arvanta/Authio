//! Local QR decoding from image files (PNG/JPEG) — no camera, no network.
//!
//! One image may hold several QR codes (a screenshot of a page, a contact sheet
//! of Google-Authenticator export pages …); every readable one is returned.

use image::{GrayImage, ImageReader, Limits};

/// Largest image file we are willing to open (screenshots are far smaller).
pub const MAX_FILE_BYTES: u64 = 40 * 1024 * 1024;
/// Largest accepted image edge, in pixels (a 8K screenshot is 7680).
const MAX_EDGE: u32 = 10_000;

fn load_gray(path: &str) -> Result<GrayImage, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot open image: {e}"))?;
    if meta.len() > MAX_FILE_BYTES {
        return Err("image file is too large".into());
    }
    // Sniff the format from magic bytes *before* falling back to the file
    // extension — screenshots saved with a mismatched .png/.jpg extension
    // must still decode (fixes "invalid png signature" on such files).
    let mut reader = ImageReader::open(path)
        .map_err(|e| format!("cannot open image: {e}"))?
        .with_guessed_format()
        .map_err(|e| format!("cannot identify image format: {e}"))?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_EDGE);
    limits.max_image_height = Some(MAX_EDGE);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    Ok(reader.decode().map_err(|e| format!("cannot decode image: {e}"))?.to_luma8())
}

fn decode_grids(img: GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let mut out: Vec<String> = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            let content = content.trim().to_string();
            if !content.is_empty() && !out.contains(&content) {
                out.push(content);
            }
        }
    }
    out
}

/// Decode EVERY QR code in the image (in reading order of detection, de-duplicated).
/// Falls back to the colour-inverted image for light-on-dark codes (dark mode).
pub fn decode_all_from_file(path: &str) -> Result<Vec<String>, String> {
    let img = load_gray(path)?;
    let mut found = decode_grids(img.clone());
    if found.is_empty() {
        let mut inv = img;
        image::imageops::invert(&mut inv);
        found = decode_grids(inv);
    }
    if found.is_empty() {
        Err("no QR code found in the image".into())
    } else {
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn rejects_empty_image() {
        let dir = std::env::temp_dir().join(format!("authio-qr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blank.png");
        // 100x100 white image — decodes to nothing.
        image::save_buffer(&path, &vec![255u8; 100 * 100 * 4], 100, 100, image::ColorType::Rgba8).unwrap();
        let err = decode_all_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no QR code"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_a_single_code() {
        let v = decode_all_from_file(&fixture("qr_a.png")).unwrap();
        assert_eq!(v.len(), 1);
        assert!(v[0].starts_with("otpauth://totp/Alpha:alice"));
    }

    #[test]
    fn reads_every_code_in_one_image() {
        let mut v = decode_all_from_file(&fixture("qr_both.png")).unwrap();
        v.sort();
        assert_eq!(v.len(), 2);
        assert!(v[0].contains("Alpha") && v[1].contains("Beta"));
    }

    #[test]
    fn reads_light_on_dark_codes() {
        let v = decode_all_from_file(&fixture("qr_a_inverted.png")).unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(decode_all_from_file("/definitely/not/here.png").is_err());
    }
}
