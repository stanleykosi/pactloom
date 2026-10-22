//! Geometry for one actually painted Host suffix. No prompt parser.
//! Only the separately compiled semantic CI observer owns the admitted suffix text.
use eframe::egui::{self, Galley, Pos2, Rect};
use egui::emath::GuiRounding;

pub(super) fn paint_origin(origin: Pos2, scale: f32) -> Pos2 { origin.round_to_pixels(scale) }

#[cfg_attr(not(wholepact_financial_rendered_host_semantic_ci), derive(Clone, Copy, Debug))]
pub(super) struct HostOutputView {
    pub rect: Rect,
    pub nonws: u64,
    pub rows: u64,
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    pub text: zeroize::Zeroizing<String>,
}
fn nonws(c: char) -> bool { !c.is_ascii_whitespace() }
fn ink_in_crop(ink: Rect, crop: Rect) -> bool { ink.is_positive() && ink.intersect(crop).is_positive() }

/// Uses the SAME galley and origin as the ordinary painted label. No re-layout,
/// scroll setter, synthetic newline or inferred prompt ID. Semantic text exists
/// only in the explicit semantic CI build, never the pixel-only profiles.
pub(super) fn visible_tail(galley: &Galley, origin: Pos2, clip: Rect,
    scale: f32, expected_nonws: u64) -> Option<HostOutputView> {
    if galley.elided || galley.rows.is_empty() || !clip.is_positive() || galley.pixels_per_point != scale
        || !scale.is_finite() || !(0.5..=4.0).contains(&scale) { return None; }
    let total = galley.rows.iter().flat_map(|r| &r.glyphs).filter(|g| nonws(g.chr)).count() as u64;
    if total != expected_nonws { return None; }
    let mut first = galley.rows.len();
    let mut bounds = Rect::NOTHING;
    let mut count = 0_u64;
    let mut rows = 0_u64;
    for (index, row) in galley.rows.iter().enumerate().rev() {
        let logical = row.rect().translate(origin.to_vec2());
        let ink = row.visuals.mesh_bounds.translate((origin + row.pos.to_vec2()).to_vec2());
        // Empty final LF row still must lie at the visible tail, not below it.
        let logical = if logical.width() == 0.0 {
            Rect::from_min_max(logical.min, egui::pos2(logical.min.x + 1.0, logical.max.y))
        } else { logical };
        if !clip.contains_rect(logical) || (ink.is_positive() && !clip.contains_rect(ink)) { break; }
        if row.glyphs.iter().any(|g| !g.chr.is_ascii()) { break; }
        first = index;
        rows += 1;
        if rows > 32 { return None; } // Never truncate to pretend completeness.
        count += row.glyphs.iter().filter(|g| nonws(g.chr)).count() as u64;
        bounds = bounds.union(logical);
        if ink.is_positive() { bounds = bounds.union(ink); }
    }
    if first == galley.rows.len() || count == 0 || count > 8192 { return None; }
    let crop = Rect::from_min_max(
        egui::pos2((bounds.min.x*scale).floor()/scale, (bounds.min.y*scale).floor()/scale),
        egui::pos2((bounds.max.x*scale).ceil()/scale, (bounds.max.y*scale).ceil()/scale));
    if !crop.is_positive() || !clip.contains_rect(crop) { return None; }
    // Outward pixel rounding must not capture ink from a clipped predecessor.
    for row in &galley.rows[..first] {
        let ink = row.visuals.mesh_bounds.translate((origin + row.pos.to_vec2()).to_vec2());
        if ink_in_crop(ink, crop) { return None; }
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    let text = rendered_suffix(galley, first)?;
    Some(HostOutputView { rect: crop, nonws: count, rows,
        #[cfg(wholepact_financial_rendered_host_semantic_ci)] text })
}

/// Recover only admitted row characters. Soft wrapping adds no characters;
/// ends_with_newline represents an actual LF in this SAME galley's layout job.
/// The equality check rejects any unaccounted shaping/elision or source mismatch.
#[cfg(wholepact_financial_rendered_host_semantic_ci)]
fn rendered_suffix(galley: &Galley, first: usize) -> Option<zeroize::Zeroizing<String>> {
    let mut text = zeroize::Zeroizing::new(String::with_capacity(8192));
    for row in &galley.rows[first..] {
        for glyph in &row.glyphs {
            if !matches!(glyph.chr, ' '..='~') || text.len() >= 8192 { return None; }
            text.push(glyph.chr);
        }
        if row.ends_with_newline {
            if text.len() >= 8192 { return None; }
            text.push('\n');
        }
    }
    let prefix_bytes = galley.rows[..first].iter().try_fold(0_usize, |length, row| {
        row.glyphs.iter().try_fold(length, |n, glyph| n.checked_add(glyph.chr.len_utf8()))?
            .checked_add(usize::from(row.ends_with_newline))
    })?;
    if text.is_empty() || galley.job.text.get(prefix_bytes..) != Some(text.as_str()) { return None; }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout(text: &str, width: f32) -> std::sync::Arc<Galley> { layout_at_scale(text, width, 1.0) }
    fn layout_at_scale(text: &str, width: f32, scale: f32) -> std::sync::Arc<Galley> {
        let ctx = egui::Context::default();
        ctx.set_pixels_per_point(scale);
        let mut result = None;
        let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
            result = Some(ui.painter().layout(text.to_owned(), egui::FontId::monospace(14.0), egui::Color32::WHITE, width));
        });
        let result = result.unwrap();
        assert_eq!(result.pixels_per_point, scale);
        result
    }
    fn end(text: &str) -> u64 { text.chars().filter(|c| nonws(*c)).count() as u64 }
    fn full(g: &Galley) -> Rect { g.rect.union(g.mesh_bounds).expand(2.0) }
    #[test]
    fn actual_wrapped_same_line_tail_has_one_count() {
        let text="first prompt: next prompt without echoed newline: ";
        let g=layout(text,130.0);
        assert!(g.rows.len()>1);
        let v=visible_tail(&g,Pos2::ZERO,full(&g),1.0,end(text)).unwrap();
        assert_eq!(v.nonws,end(text));assert_eq!(v.rows,g.rows.len() as u64);
    }
    #[test]
    fn trailing_empty_lf_row_is_not_new_content() {
        let a=layout("prompt: ",500.0);let b=layout("prompt: \n",500.0);
        assert_eq!(visible_tail(&a,Pos2::ZERO,full(&a),1.0,7).unwrap().nonws,
                   visible_tail(&b,Pos2::ZERO,full(&b),1.0,7).unwrap().nonws);
    }
    #[test]
    fn hidden_tail_and_horizontal_clip_are_ineligible() {
        let g=layout("one\ntwo\nlast prompt: ",500.0);
        let clip=Rect::from_min_max(egui::pos2(-2.0,-2.0),egui::pos2(500.0,g.rows[1].pos.y));
        assert!(visible_tail(&g,Pos2::ZERO,clip,1.0,17).is_none());
        let g=layout("long prompt: ",500.0);
        let clip=Rect::from_min_max(egui::pos2(-2.0,-2.0),egui::pos2(10.0,100.0));
        assert!(visible_tail(&g,Pos2::ZERO,clip,1.0,end("long prompt: ")).is_none());
    }
    #[test]
    fn long_transcript_visible_suffix_does_not_require_whole_line() {
        let text="old startup historical session enrollment ".repeat(80)+"current prompt: ";
        let g=layout(&text,400.0);assert!(g.rect.height()>240.0);
        let clip=Rect::from_min_max(egui::pos2(-2.0,g.rect.bottom()-220.0),egui::pos2(402.0,g.rect.bottom()+2.0));
        let v=visible_tail(&g,Pos2::ZERO,clip,1.0,end(&text)).unwrap();
        assert!(v.nonws<end(&text));assert!(v.rows<=32);
    }
    #[test]
    fn non_ascii_tail_and_too_many_rows_refuse() {
        let g=layout("tail é",500.0);
        assert!(visible_tail(&g,Pos2::ZERO,full(&g),1.0,end("tail é")).is_none());
        let text="row\n".repeat(40);let g=layout(&text,500.0);
        assert!(visible_tail(&g,Pos2::ZERO,full(&g),1.0,end(&text)).is_none());
    }
    #[test]
    fn boundary_contact_is_not_positive_ink_overlap() {
        let g=layout("preceding row\ncurrent prompt: ",500.0);
        let row=&g.rows[0];
        let ink=row.visuals.mesh_bounds.translate(row.pos.to_vec2());
        let touching=Rect::from_min_max(egui::pos2(ink.min.x,ink.max.y),egui::pos2(ink.max.x,ink.max.y+20.0));
        assert!(!ink_in_crop(ink,touching));
        let overlapping=touching.translate(egui::vec2(0.0,-0.25));
        assert!(ink_in_crop(ink,overlapping));
    }
    #[test]
    fn fractional_paint_origin_uses_exact_pinned_pixel_rounding() {
        for scale in [0.5, 1.5, 4.0] {
            for offset in [-0.51, -0.17, 0.17, 0.51] {
                let origin = paint_origin(egui::pos2(offset, offset), scale);
                assert_eq!(origin.x * scale, (offset * scale).round());
                assert_eq!(origin.y * scale, (offset * scale).round());
                let g=layout_at_scale("prompt: ",500.0,scale);
                let clip=full(&g).translate(origin.to_vec2()).expand(1.0);
                assert!(visible_tail(&g,origin,clip,scale,7).is_some());
            }
        }
    }
    #[test]
    fn wrong_count_and_unsafe_pixel_rounding_refuse() {
        let g=layout("prompt: ",500.0);
        assert!(visible_tail(&g,Pos2::ZERO,full(&g),1.0,999).is_none());
        let g=layout_at_scale("prompt: ",500.0,1.5);
        let tight=g.rect.union(g.mesh_bounds);
        let shifted=egui::pos2(0.13,0.17);let clip=tight.translate(shifted.to_vec2());
        assert!(visible_tail(&g,shifted,clip,1.5,7).is_none());
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    #[test]
    fn semantic_wraps_preserve_spaces_real_lf_and_exact_challenge() {
        let text = "old prompt: new prompt: \nExact random challenge O0Il1S5B8-0123456789abcdef: ";
        let g = layout(text, 180.0);
        assert!(g.rows.len() > 2);
        let view = visible_tail(&g, Pos2::ZERO, full(&g), 1.0, end(text)).unwrap();
        assert_eq!(view.text.as_str(), text);
        assert_eq!(view.text.bytes().filter(|b| *b == b'\n').count(), 1);
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    #[test]
    fn semantic_clipped_prefix_is_not_disclosed_or_normalized() {
        let text = "hidden history ".repeat(80) + "\ncurrent challenge 0O1l: \n";
        let g = layout(&text, 400.0);
        let clip = Rect::from_min_max(egui::pos2(-2.0, g.rect.bottom() - 100.0), egui::pos2(402.0, g.rect.bottom() + 2.0));
        let view = visible_tail(&g, Pos2::ZERO, clip, 1.0, end(&text)).unwrap();
        assert!(text.ends_with(view.text.as_str()));
        assert!(view.text.len() < text.len());
        assert!(view.text.ends_with("current challenge 0O1l: \n"));
        assert_eq!(end(&view.text), view.nonws);
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    #[test]
    fn semantic_total_bytes_not_just_nonwhitespace_are_bounded() {
        let text = "a".to_owned() + &" ".repeat(8191);
        let g = layout(&text, 200000.0);
        assert_eq!(visible_tail(&g, Pos2::ZERO, full(&g), 1.0, 1).unwrap().text.len(), 8192);
        let text = text + " ";
        let g = layout(&text, 200000.0);
        assert!(visible_tail(&g, Pos2::ZERO, full(&g), 1.0, 1).is_none());
        let g = layout("prompt\t", 500.0);
        assert!(visible_tail(&g, Pos2::ZERO, full(&g), 1.0, end("prompt\t")).is_none());
    }
    #[cfg(wholepact_financial_rendered_host_semantic_ci)]
    #[test]
    fn semantic_uses_exact_painted_label_galley_without_relayout() {
        let ctx = egui::Context::default();
        let mut painted = None;
        let mut raw = egui::RawInput::default();
        raw.screen_rect = Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0)));
        let output = ctx.run_ui(raw, |ui| {
            let (origin, galley, _) = egui::Label::new(egui::RichText::new("Challenge: 0OIl1 abcdef\n").monospace()).selectable(false).layout_in_ui(ui);
            let origin = paint_origin(origin, ui.ctx().pixels_per_point());
            ui.painter().galley(origin, galley.clone(), ui.visuals().text_color());
            let view = visible_tail(&galley, origin, ui.clip_rect(), 1.0, end(&galley.job.text)).unwrap();
            assert_eq!(view.text.as_str(), galley.job.text.as_str());
            painted = Some(galley);
        });
        let painted = painted.unwrap();
        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if std::sync::Arc::ptr_eq(&text.galley, &painted))));
    }

}
