//! Window placement (Electron: `terminalPopupPlacement.cjs` and
//! `resolveSettingsWindowBounds`). Pure geometry; all rectangles share one
//! coordinate space (the caller uses physical pixels).

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect {
    pub const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    fn area(&self) -> f64 {
        self.width.max(0.0) * self.height.max(0.0)
    }
}

pub fn intersects(a: &Rect, b: &Rect) -> bool {
    a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y
}

fn clamp(value: f64, min: f64, max: f64) -> f64 {
    if max < min {
        return min;
    }
    value.max(min).min(max)
}

fn finish_frame(x: f64, y: f64, width: f64, height: f64, work_area: &Rect) -> Rect {
    let width = width.min(work_area.width).round();
    let height = height.min(work_area.height).round();
    let max_x = work_area.x + work_area.width - width;
    let max_y = work_area.y + work_area.height - height;
    Rect::new(
        clamp(x, work_area.x, max_x).round(),
        clamp(y, work_area.y, max_y).round(),
        width,
        height,
    )
}

fn intersection(a: &Rect, b: &Rect) -> Rect {
    let x = a.x.max(b.x);
    let y = a.y.max(b.y);
    let right = (a.x + a.width).min(b.x + b.width);
    let bottom = (a.y + a.height).min(b.y + b.height);
    Rect::new(
        x.ceil(),
        y.ceil(),
        right.floor() - x.ceil(),
        bottom.floor() - y.ceil(),
    )
}

/// Centre a `width` x `height` frame on `source`, kept inside `work_area`
/// (Electron: `resolveSettingsWindowBounds`).
pub fn center_on(work_area: &Rect, source: &Rect, width: f64, height: f64) -> Rect {
    finish_frame(
        source.x + (source.width - width) / 2.0,
        source.y + (source.height - height) / 2.0,
        width,
        height,
        work_area,
    )
}

/// Place a terminal popup in the largest region of the source window that
/// does not cover `avoid` (the system-manager panel). Without a usable gap,
/// centre on the source window.
pub fn place_terminal_popup(
    work_area: &Rect,
    source: &Rect,
    avoid: Option<&Rect>,
    width: f64,
    height: f64,
    min_width: f64,
    min_height: f64,
) -> Rect {
    let preferred_w = width.min(work_area.width);
    let preferred_h = height.min(work_area.height);
    let centered_fallback = || center_on(work_area, source, preferred_w, preferred_h);
    let Some(avoid) = avoid.filter(|a| a.width > 0.0 && a.height > 0.0) else {
        return centered_fallback();
    };

    let source_right = source.x + source.width;
    let source_bottom = source.y + source.height;
    let avoid_right = avoid.x + avoid.width;
    let avoid_bottom = avoid.y + avoid.height;
    let slots = [
        Rect::new(source.x, source.y, avoid.x - source.x, source.height),
        Rect::new(
            avoid_right,
            source.y,
            source_right - avoid_right,
            source.height,
        ),
        Rect::new(source.x, source.y, source.width, avoid.y - source.y),
        Rect::new(
            source.x,
            avoid_bottom,
            source.width,
            source_bottom - avoid_bottom,
        ),
    ];
    let visible = slots
        .iter()
        .filter(|r| r.width >= 1.0 && r.height >= 1.0)
        .map(|r| intersection(r, work_area))
        .filter(|r| r.width >= min_width && r.height >= min_height)
        .fold(None::<Rect>, |best, r| match best {
            Some(b) if b.area() >= r.area() => Some(b),
            _ => Some(r),
        });
    let Some(slot) = visible else {
        return centered_fallback();
    };

    let popup_w = preferred_w.min(slot.width);
    let popup_h = preferred_h.min(slot.height);
    let centered = finish_frame(
        slot.x + (slot.width - popup_w) / 2.0,
        slot.y + (slot.height - popup_h) / 2.0,
        popup_w,
        popup_h,
        work_area,
    );
    if !intersects(&centered, avoid) {
        return centered;
    }
    let pinned = finish_frame(slot.x, slot.y, popup_w, popup_h, work_area);
    if intersects(&pinned, avoid) {
        centered_fallback()
    } else {
        pinned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORK: Rect = Rect::new(0.0, 0.0, 1440.0, 900.0);
    const SOURCE: Rect = Rect::new(0.0, 0.0, 1440.0, 900.0);

    fn place(source: &Rect, avoid: Rect) -> Rect {
        place_terminal_popup(&WORK, source, Some(&avoid), 920.0, 580.0, 480.0, 320.0)
    }

    #[test]
    fn beside_a_right_side_panel() {
        let avoid = Rect::new(1000.0, 40.0, 440.0, 860.0);
        let frame = place(&SOURCE, avoid);
        assert!(!intersects(&frame, &avoid));
        assert!(frame.x + frame.width <= avoid.x);
        assert_eq!((frame.width, frame.height), (920.0, 580.0));
    }

    #[test]
    fn beside_a_left_side_panel() {
        let avoid = Rect::new(0.0, 36.0, 420.0, 864.0);
        let frame = place(&SOURCE, avoid);
        assert!(!intersects(&frame, &avoid));
        assert!(frame.x >= avoid.x + avoid.width);
    }

    #[test]
    fn above_a_bottom_dock() {
        let avoid = Rect::new(0.0, 620.0, 1440.0, 280.0);
        let frame = place(&SOURCE, avoid);
        assert!(!intersects(&frame, &avoid));
        assert!(frame.y + frame.height <= avoid.y);
    }

    #[test]
    fn off_screen_source_stays_in_work_area_and_off_the_panel() {
        let avoid = Rect::new(500.0, 0.0, 440.0, 900.0);
        let frame = place(&Rect::new(-500.0, 0.0, 1440.0, 900.0), avoid);
        assert!(!intersects(&frame, &avoid));
        assert!(frame.x >= WORK.x && frame.y >= WORK.y);
        assert!(frame.x + frame.width <= WORK.x + WORK.width);
        assert!(frame.y + frame.height <= WORK.y + WORK.height);
        assert!(frame.width >= 480.0 && frame.height >= 320.0);
    }

    #[test]
    fn without_a_panel_the_popup_is_centred_on_the_source() {
        let frame = place_terminal_popup(&WORK, &SOURCE, None, 920.0, 580.0, 480.0, 320.0);
        assert_eq!(frame, Rect::new(260.0, 160.0, 920.0, 580.0));
        // Larger than the work area: shrunk and kept inside.
        let small = Rect::new(0.0, 0.0, 800.0, 500.0);
        let frame = place_terminal_popup(&small, &small, None, 920.0, 580.0, 480.0, 320.0);
        assert_eq!(frame, Rect::new(0.0, 0.0, 800.0, 500.0));
    }
}
