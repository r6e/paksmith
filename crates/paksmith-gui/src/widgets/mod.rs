/// UI widget components for the paksmith explorer.
pub mod audio_player;
pub mod context_menu;
pub mod export_picker;
pub mod file_tree;
pub mod hex_view;
pub mod inline_band;
pub mod property_tree;
pub mod tab_bar;
pub mod texture_viewer;
pub mod toast;

/// Push a spacer of `px` height standing in for the rows outside a windowed
/// view's range — shared by the file tree, hex grid, and property inspector
/// (#660).
///
/// The `> 0` guard is load-bearing, and having it in ONE place is the point:
/// pushing a zero-height `Space` would still occupy a child slot and shift
/// the sibling widgets' positions in iced's tree diff, which the
/// scroll-restore path depends on staying stable (see
/// `app::restore_scroll_positions`) — "no spacer" and "zero-height spacer"
/// must be the same case on every surface.
pub(crate) fn push_spacer<'a, M: 'a>(items: &mut Vec<iced::Element<'a, M>>, px: f32) {
    if px > 0.0 {
        items.push(iced::widget::Space::new().height(px).into());
    }
}

#[cfg(test)]
mod tests {
    use super::push_spacer;

    #[test]
    fn push_spacer_skips_zero_and_negative_heights() {
        let mut items: Vec<iced::Element<'_, ()>> = Vec::new();
        push_spacer(&mut items, 0.0);
        push_spacer(&mut items, -1.0);
        assert!(
            items.is_empty(),
            "a zero/negative spacer must not occupy a child slot — it would \
             shift sibling positions in iced's tree diff"
        );
    }

    #[test]
    fn push_spacer_pushes_one_element_for_positive_height() {
        let mut items: Vec<iced::Element<'_, ()>> = Vec::new();
        push_spacer(&mut items, 12.5);
        assert_eq!(items.len(), 1);
    }
}
