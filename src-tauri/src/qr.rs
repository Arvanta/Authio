//! Local QR decoding from image files (PNG/JPEG) — no camera, no network.

pub fn decode_qr_from_file(path: &str) -> Result<String, String> {
    let img = image::open(path)
        .map_err(|e| format!("cannot open image: {e}"))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.trim().is_empty() {
                return Ok(content);
            }
        }
    }
    Err("no QR code found in the image".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_image() {
        let dir = std::env::temp_dir().join(format!("authio-qr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blank.png");
        // 100x100 white image — decodes to nothing.
        image::save_buffer(
            &path,
            &vec![255u8; 100 * 100 * 4],
            100,
            100,
            image::ColorType::Rgba8,
        )
        .unwrap();
        let err = decode_qr_from_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("no QR code"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
