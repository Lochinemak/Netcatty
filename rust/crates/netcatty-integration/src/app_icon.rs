//! App icon variants (Electron: `electron/bridges/appIconManager.cjs` and the
//! Windows tray artwork in `globalShortcutBridge.cjs`): variant names, which
//! bundled asset each platform uses, and the tray-sized rendition of a
//! variant (transparent margin cropped, scaled to the small-icon size).

pub const VARIANTS: &[&str] = &[
    "original",
    "bright",
    "dark",
    "colorful",
    "high-contrast",
    "white-navy",
    "white-sky",
    "white-rose",
    "white-emerald",
    "white-amber",
    "white-violet",
    "rainbow",
];

pub const DEFAULT_VARIANT: &str = "original";

pub fn is_valid_variant(variant: &str) -> bool {
    VARIANTS.contains(&variant)
}

pub fn normalize_variant(variant: Option<&str>) -> &'static str {
    variant
        .and_then(|v| VARIANTS.iter().copied().find(|known| *known == v))
        .unwrap_or(DEFAULT_VARIANT)
}

/// Asset paths (relative to the renderer's `public/` / `dist/` root) tried in
/// order for `variant`. macOS uses the HIG-sized artwork (with the system
/// margin) and never falls back to the full-bleed Windows icon; elsewhere
/// the original also falls back to `icon-win.png` / `icon.png`.
pub fn asset_candidates(variant: &str, is_mac: bool) -> Vec<String> {
    let variant = normalize_variant(Some(variant));
    let dir = if is_mac { "icons/variants/macos" } else { "icons/variants" };
    let mut out = vec![format!("{dir}/{variant}.png")];
    if variant == DEFAULT_VARIANT && !is_mac {
        out.push("icon-win.png".to_owned());
        out.push("icon.png".to_owned());
    }
    out
}

/// Decoded RGBA8 image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rgba {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

/// Decode a PNG into RGBA8.
pub fn decode_png(bytes: &[u8]) -> Option<Rgba> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    let pixels = match info.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => buf
            .chunks_exact(3)
            .flat_map(|c| [c[0], c[1], c[2], 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => buf
            .chunks_exact(2)
            .flat_map(|c| [c[0], c[0], c[0], c[1]])
            .collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => return None,
    };
    Some(Rgba {
        width: info.width,
        height: info.height,
        pixels,
    })
}

/// Crop the transparent margin (alpha <= 16) to a centred square with one
/// pixel of padding, like Electron's `cropTransparentMargin`.
pub fn crop_transparent_margin(image: &Rgba) -> Rgba {
    let (w, h) = (image.width as i64, image.height as i64);
    if w == 0 || h == 0 || image.pixels.len() != (w * h * 4) as usize {
        return image.clone();
    }
    let (mut min_x, mut min_y, mut max_x, mut max_y) = (w, h, -1, -1);
    for y in 0..h {
        for x in 0..w {
            if image.pixels[((y * w + x) * 4 + 3) as usize] <= 16 {
                continue;
            }
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
    }
    if max_x < min_x || max_y < min_y {
        return image.clone();
    }
    let box_left = (min_x - 1).max(0);
    let box_top = (min_y - 1).max(0);
    let box_right = (max_x + 1).min(w - 1);
    let box_bottom = (max_y + 1).min(h - 1);
    let side = (box_right - box_left + 1)
        .max(box_bottom - box_top + 1)
        .min(w)
        .min(h);
    let js_round = |v: f64| (v + 0.5).floor() as i64;
    let left = js_round((box_left + box_right) as f64 / 2.0 - (side - 1) as f64 / 2.0).clamp(0, w - side);
    let top = js_round((box_top + box_bottom) as f64 / 2.0 - (side - 1) as f64 / 2.0).clamp(0, h - side);
    if left == 0 && top == 0 && side == w && side == h {
        return image.clone();
    }
    let mut pixels = Vec::with_capacity((side * side * 4) as usize);
    for y in top..top + side {
        let start = ((y * w + left) * 4) as usize;
        pixels.extend_from_slice(&image.pixels[start..start + (side * 4) as usize]);
    }
    Rgba {
        width: side as u32,
        height: side as u32,
        pixels,
    }
}

/// Area-average downscale (premultiplied, so transparent edges do not darken).
pub fn resize(image: &Rgba, width: u32, height: u32) -> Rgba {
    let (sw, sh) = (image.width as f64, image.height as f64);
    let mut pixels = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        let y0 = y as f64 * sh / height as f64;
        let y1 = (y + 1) as f64 * sh / height as f64;
        for x in 0..width {
            let x0 = x as f64 * sw / width as f64;
            let x1 = (x + 1) as f64 * sw / width as f64;
            let mut acc = [0.0f64; 4];
            let mut total = 0.0;
            let mut sy = y0.floor() as u32;
            while (sy as f64) < y1 && sy < image.height {
                let wy = ((sy + 1) as f64).min(y1) - (sy as f64).max(y0);
                let mut sx = x0.floor() as u32;
                while (sx as f64) < x1 && sx < image.width {
                    let wx = ((sx + 1) as f64).min(x1) - (sx as f64).max(x0);
                    let weight = wx * wy;
                    let i = ((sy * image.width + sx) * 4) as usize;
                    let alpha = image.pixels[i + 3] as f64 / 255.0;
                    acc[0] += image.pixels[i] as f64 * alpha * weight;
                    acc[1] += image.pixels[i + 1] as f64 * alpha * weight;
                    acc[2] += image.pixels[i + 2] as f64 * alpha * weight;
                    acc[3] += alpha * weight;
                    total += weight;
                    sx += 1;
                }
                sy += 1;
            }
            if total <= 0.0 || acc[3] <= 0.0 {
                pixels.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let a = acc[3] / total;
            let channel = |v: f64| (v / acc[3]).round().clamp(0.0, 255.0) as u8;
            pixels.extend_from_slice(&[
                channel(acc[0]),
                channel(acc[1]),
                channel(acc[2]),
                (a * 255.0).round().clamp(0.0, 255.0) as u8,
            ]);
        }
    }
    Rgba {
        width,
        height,
        pixels,
    }
}

/// Windows small-icon size (`SM_CXSMICON`): 16px at 100%, scaled with DPI.
pub fn small_icon_px(scale_factor: f64) -> u32 {
    let scale = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor
    } else {
        1.0
    };
    ((16.0 * scale).round() as u32).max(16)
}

/// Tray rendition of a variant PNG: cropped artwork scaled to `size` px.
pub fn tray_rendition(png_bytes: &[u8], size: u32) -> Option<Rgba> {
    let decoded = decode_png(png_bytes)?;
    let cropped = crop_transparent_margin(&decoded);
    Some(resize(&cropped, size, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(width: u32, height: u32, opaque: impl Fn(u32, u32) -> bool) -> Rgba {
        let mut pixels = Vec::new();
        for y in 0..height {
            for x in 0..width {
                if opaque(x, y) {
                    pixels.extend_from_slice(&[200, 100, 50, 255]);
                } else {
                    pixels.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
        }
        Rgba { width, height, pixels }
    }

    #[test]
    fn variants_normalize_to_original() {
        assert_eq!(normalize_variant(Some("nope")), "original");
        assert_eq!(normalize_variant(Some("bright")), "bright");
        assert_eq!(normalize_variant(None), "original");
        assert!(is_valid_variant("white-violet"));
        assert_eq!(VARIANTS.len(), 12);
    }

    #[test]
    fn platform_specific_assets() {
        assert_eq!(asset_candidates("bright", true), vec!["icons/variants/macos/bright.png"]);
        assert_eq!(asset_candidates("bright", false), vec!["icons/variants/bright.png"]);
        assert_eq!(
            asset_candidates("original", false),
            vec!["icons/variants/original.png", "icon-win.png", "icon.png"]
        );
        // macOS never falls back to the full-bleed Windows artwork.
        assert_eq!(asset_candidates("original", true), vec!["icons/variants/macos/original.png"]);
        assert_eq!(asset_candidates("bogus", true), vec!["icons/variants/macos/original.png"]);
    }

    #[test]
    fn crop_removes_the_transparent_margin() {
        let image = solid(20, 20, |x, y| (5..15).contains(&x) && (5..15).contains(&y));
        let cropped = crop_transparent_margin(&image);
        assert_eq!((cropped.width, cropped.height), (12, 12));
        // Fully opaque or fully transparent images are returned unchanged.
        let full = solid(4, 4, |_, _| true);
        assert_eq!(crop_transparent_margin(&full), full);
        let empty = solid(4, 4, |_, _| false);
        assert_eq!(crop_transparent_margin(&empty), empty);
    }

    #[test]
    fn resize_keeps_colour_and_alpha() {
        let image = solid(32, 32, |_, _| true);
        let small = resize(&image, 16, 16);
        assert_eq!(small.pixels.len(), 16 * 16 * 4);
        assert_eq!(&small.pixels[0..4], &[200, 100, 50, 255]);
        let half = solid(2, 1, |x, _| x == 0);
        let one = resize(&half, 1, 1);
        assert_eq!(&one.pixels[0..3], &[200, 100, 50]);
        assert_eq!(one.pixels[3], 128);
    }

    #[test]
    fn small_icon_size_follows_dpi() {
        assert_eq!(small_icon_px(1.0), 16);
        assert_eq!(small_icon_px(1.5), 24);
        assert_eq!(small_icon_px(0.5), 16);
        assert_eq!(small_icon_px(f64::NAN), 16);
    }

    #[test]
    fn bundled_variant_artwork_decodes_into_a_tray_rendition() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../public/icons/variants/bright.png");
        let bytes = std::fs::read(path).expect("variant artwork");
        let tray = tray_rendition(&bytes, 24).expect("decodes");
        assert_eq!((tray.width, tray.height), (24, 24));
        assert_eq!(tray.pixels.len(), 24 * 24 * 4);
    }
}
