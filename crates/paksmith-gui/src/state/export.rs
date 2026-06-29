//! Pure model for the Export As… inline picker. No iced imports — unit + mutation
//! tested. The picker is keyed by entry path (see [`ExportMenu`]).

use paksmith_core::export::ExportFormat;

/// One choice in the Export As… picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportChoice {
    /// Export payload `payload_idx` as a file with `extension` via its handler.
    Typed {
        payload_idx: usize,
        extension: &'static str,
    },
    /// Write the entry's raw decompressed bytes verbatim (no parse, no handler).
    Raw,
}

/// The open Export As… picker, keyed by entry **path** (not row index) so a tree
/// reshuffle between the async enumerate and its result can't mis-target it —
/// the same path-keying every async result in `app.rs` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportMenu {
    /// Archive entry path the picker exports.
    pub path: String,
    /// Format buttons, in order, always ending with [`ExportChoice::Raw`].
    pub choices: Vec<ExportChoice>,
}

/// Map enumerated formats to picker choices: one [`ExportChoice::Typed`] per
/// [`ExportFormat`] (order preserved), then a trailing [`ExportChoice::Raw`].
/// Raw is always present — it works even when nothing parsed or no handler
/// matched.
#[must_use]
pub fn export_choices(formats: &[ExportFormat]) -> Vec<ExportChoice> {
    let mut choices: Vec<ExportChoice> = formats
        .iter()
        .map(|f| ExportChoice::Typed {
            payload_idx: f.payload_idx,
            extension: f.extension,
        })
        .collect();
    choices.push(ExportChoice::Raw);
    choices
}

/// Button label: the uppercased extension for a typed format, `"Raw bytes"`
/// for the raw entry.
#[must_use]
pub fn choice_label(choice: &ExportChoice) -> String {
    match choice {
        ExportChoice::Typed { extension, .. } => extension.to_uppercase(),
        ExportChoice::Raw => "Raw bytes".to_string(),
    }
}

/// Default file name the save dialog opens with, derived from the entry path.
/// Typed → `<stem>.<extension>`; Raw → the entry's own basename (raw bytes are
/// the entry's own content, so its name is the natural default).
#[must_use]
pub fn default_export_filename(path: &str, choice: &ExportChoice) -> String {
    let basename = path.rsplit('/').next().unwrap_or(path);
    match choice {
        ExportChoice::Typed { extension, .. } => {
            let stem = basename.rsplit_once('.').map_or(basename, |(s, _)| s);
            format!("{stem}.{extension}")
        }
        ExportChoice::Raw => basename.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(idx: usize, ext: &'static str) -> ExportFormat {
        ExportFormat {
            payload_idx: idx,
            extension: ext,
        }
    }

    #[test]
    fn export_choices_maps_then_appends_raw() {
        let choices = export_choices(&[fmt(0, "png"), fmt(1, "json")]);
        assert_eq!(
            choices,
            vec![
                ExportChoice::Typed {
                    payload_idx: 0,
                    extension: "png"
                },
                ExportChoice::Typed {
                    payload_idx: 1,
                    extension: "json"
                },
                ExportChoice::Raw,
            ]
        );
    }

    #[test]
    fn export_choices_empty_formats_is_raw_only() {
        assert_eq!(export_choices(&[]), vec![ExportChoice::Raw]);
    }

    #[test]
    fn choice_label_uppercases_extension_and_names_raw() {
        assert_eq!(
            choice_label(&ExportChoice::Typed {
                payload_idx: 0,
                extension: "png"
            }),
            "PNG"
        );
        assert_eq!(choice_label(&ExportChoice::Raw), "Raw bytes");
    }

    #[test]
    fn default_filename_typed_swaps_extension_on_stem() {
        let c = ExportChoice::Typed {
            payload_idx: 0,
            extension: "png",
        };
        assert_eq!(
            default_export_filename("Game/Tex/T_Rock.uasset", &c),
            "T_Rock.png"
        );
        // No directory and no dot: stem is the whole basename.
        assert_eq!(default_export_filename("Rock", &c), "Rock.png");
    }

    #[test]
    fn default_filename_raw_keeps_entry_basename() {
        let c = ExportChoice::Raw;
        assert_eq!(
            default_export_filename("Game/Tex/T_Rock.uasset", &c),
            "T_Rock.uasset"
        );
        assert_eq!(default_export_filename("loose.bin", &c), "loose.bin");
    }
}
