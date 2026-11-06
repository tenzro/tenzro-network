//! Live resource accounting for the onboarding model picker.
//!
//! An operator choosing what to serve is spending two budgets at once:
//! RAM, which every loaded model holds for as long as it is served, and
//! disk, which every downloaded model holds permanently and which a
//! storage pledge competes for directly. Picking a 12B model has to
//! visibly remove the 8B model from reach in the same instant, or the
//! screen is lying.
//!
//! So every entry carries one of three states rather than a boolean.
//! "Fits", "would fit but not alongside what you have already chosen",
//! and "will never fit on this machine" are three different pieces of
//! news, and collapsing the middle one into "unavailable" is what makes
//! this kind of UI feel broken — the operator deselects something and
//! cannot work out why nothing changed.

use serde::{Deserialize, Serialize};

use tenzro_model::catalog::HfModelEntry;

/// RAM held back for the operating system, the app, and the node itself.
///
/// The node is not a thin client: it carries RocksDB, an iroh endpoint, and
/// the consensus engine when validating. A quarter of RAM with a 2 GB
/// floor leaves a 8 GB laptop 6 GB of model budget and a 64 GB
/// workstation 48 GB, which matches what those machines actually sustain.
fn system_reserve_gb(ram_gb: u32) -> u32 {
    (ram_gb / 4).max(2)
}

/// Whether a model can be served given the machine and the rest of the
/// current selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fit {
    /// Can be added to the current selection.
    Fits,
    /// Would fit on this machine alone, but not alongside what is already
    /// selected. Deselecting something brings it back.
    Blocked,
    /// Will never fit on this machine, whatever else is deselected.
    Unsupported,
}

/// One catalogue entry, projected against this machine and this selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelBudgetEntry {
    pub id: String,
    pub name: String,
    pub family: String,
    pub parameters: String,
    pub quantization: String,
    pub context_length: u32,
    /// The licence the network catalog names for this model, if it lists one.
    pub license: Option<String>,
    pub description: String,
    /// Download size in bytes.
    pub size_bytes: u64,
    /// RAM the model needs once loaded, in whole GB.
    pub min_ram_gb: u32,
    /// Already present in `~/.tenzro/models`.
    pub downloaded: bool,
    /// Bytes it currently occupies on disk. Zero when not downloaded.
    pub on_disk_bytes: u64,
    /// Accepts image input (needs a projector alongside the GGUF).
    pub vision: bool,
    /// Mixture-of-Experts. Holds full weights in RAM but activates only a
    /// slice per token, so it is far faster than its size suggests.
    pub moe: bool,
    /// In the operator's current selection.
    pub selected: bool,
    pub fit: Fit,
    /// Why, when `fit` is not `Fits`. Written for the operator, not for a log.
    pub reason: Option<String>,
}

/// The whole budget: both ceilings, what is spoken for, and every entry
/// classified against the remainder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetReadout {
    /// Total system RAM, GB.
    pub ram_total_gb: u32,
    /// Held back for the OS, the app and the node.
    pub ram_reserved_gb: u32,
    /// Committed by the current model selection.
    pub ram_selected_gb: u32,
    /// Still available to select against.
    pub ram_available_gb: u32,
    /// Free disk on the home volume, GB.
    pub disk_total_gb: u32,
    /// Held back so a storage pledge cannot fill the boot volume.
    pub disk_reserved_gb: u32,
    /// Downloads the current selection still has to perform, GB.
    pub disk_downloads_gb: u32,
    /// Gigabytes pledged to the storage role.
    pub disk_storage_gb: u32,
    /// Still available to select or pledge against.
    pub disk_available_gb: u32,
    /// Every catalogue entry this machine could be shown.
    pub models: Vec<ModelBudgetEntry>,
}

/// Bytes to whole GB, rounded up — a 4.2 GB model spends 5 GB of a
/// GB-granular budget, and rounding down would let a selection creep past
/// the ceiling one fraction at a time.
fn bytes_to_gb_ceil(bytes: u64) -> u32 {
    const GB: u64 = 1024 * 1024 * 1024;
    bytes.div_ceil(GB) as u32
}

/// Projects the catalogue against this machine, this selection, and this
/// storage pledge.
///
/// `selected` are catalogue ids the operator has chosen; `storage_pledge_gb`
/// is what they have offered the storage role. Both budgets are evaluated
/// together because they draw on the same disk.
///
/// A model already on disk costs nothing further to keep — its bytes are
/// already missing from the free-space figure — so only undownloaded
/// selections are charged against disk. The vision projector that ships
/// alongside a multimodal GGUF is a few hundred megabytes that the
/// catalogue does not size; the disk reserve absorbs it rather than this
/// function inventing a figure.
pub fn compute(selected: &[String], storage_pledge_gb: u32) -> BudgetReadout {
    let profile = crate::hardware::HardwareProfile::detect();
    let readout = profile.readout();

    let ram_total_gb = readout.ram_gb;
    let ram_reserved_gb = system_reserve_gb(ram_total_gb).min(ram_total_gb);
    let ram_ceiling_gb = ram_total_gb - ram_reserved_gb;

    let disk_total_gb = readout.free_disk_gb;
    let disk_reserved_gb = disk_total_gb.saturating_sub(readout.offerable_storage_gb);
    let disk_ceiling_gb = readout.offerable_storage_gb;

    let catalog = tenzro_model::catalog::get_model_catalog();

    // First pass: resolve on-disk facts and the cost of each selection.
    struct Resolved {
        entry: HfModelEntry,
        downloaded: bool,
        on_disk_bytes: u64,
        selected: bool,
    }

    let resolved: Vec<Resolved> = catalog
        .into_iter()
        .filter(|e| e.promotable)
        .map(|entry| {
            let (downloaded, on_disk_bytes, _) = crate::rpc::on_disk(&entry);
            let selected = selected.iter().any(|s| s == &entry.id);
            Resolved {
                entry,
                downloaded,
                on_disk_bytes,
                selected,
            }
        })
        .collect();

    let ram_selected_gb: u32 = resolved
        .iter()
        .filter(|r| r.selected)
        .map(|r| r.entry.min_ram_gb)
        .sum();

    let download_bytes: u64 = resolved
        .iter()
        .filter(|r| r.selected && !r.downloaded)
        .map(|r| r.entry.size_bytes)
        .sum();
    let disk_downloads_gb = bytes_to_gb_ceil(download_bytes);

    let disk_spent_gb = disk_downloads_gb.saturating_add(storage_pledge_gb);
    let disk_available_gb = disk_ceiling_gb.saturating_sub(disk_spent_gb);
    let ram_available_gb = ram_ceiling_gb.saturating_sub(ram_selected_gb);

    // Second pass: classify. A selected entry is measured against the
    // budget with its own cost added back, so it never reports itself as
    // blocked by itself.
    let models = resolved
        .iter()
        .map(|r| {
            let cost_ram = r.entry.min_ram_gb;
            let cost_disk = if r.downloaded {
                0
            } else {
                bytes_to_gb_ceil(r.entry.size_bytes)
            };

            let (headroom_ram, headroom_disk) = if r.selected {
                (
                    ram_available_gb.saturating_add(cost_ram),
                    disk_available_gb.saturating_add(cost_disk),
                )
            } else {
                (ram_available_gb, disk_available_gb)
            };

            let (fit, reason) = classify(
                cost_ram,
                cost_disk,
                headroom_ram,
                headroom_disk,
                ram_ceiling_gb,
                disk_ceiling_gb,
            );

            ModelBudgetEntry {
                id: r.entry.id.clone(),
                name: r.entry.name.clone(),
                family: r.entry.family.clone(),
                parameters: r.entry.parameters.clone(),
                quantization: r.entry.quantization.clone(),
                context_length: r.entry.context_length,
                license: tenzro_model::catalog::entry(&r.entry.id).map(|e| e.licence.name),
                description: r.entry.description.clone(),
                size_bytes: r.entry.size_bytes,
                min_ram_gb: r.entry.min_ram_gb,
                downloaded: r.downloaded,
                on_disk_bytes: r.on_disk_bytes,
                vision: r.entry.mmproj.is_some(),
                moe: r.entry.moe.is_some(),
                selected: r.selected,
                fit,
                reason,
            }
        })
        .collect();

    BudgetReadout {
        ram_total_gb,
        ram_reserved_gb,
        ram_selected_gb,
        ram_available_gb,
        disk_total_gb,
        disk_reserved_gb,
        disk_downloads_gb,
        disk_storage_gb: storage_pledge_gb,
        disk_available_gb,
        models,
    }
}

/// Decides between the three states, and writes the operator-facing reason.
///
/// The machine ceilings are checked first: a model that exceeds them is
/// `Unsupported` no matter what is deselected, and telling someone to free
/// up space they do not have is worse than telling them the truth.
fn classify(
    cost_ram: u32,
    cost_disk: u32,
    headroom_ram: u32,
    headroom_disk: u32,
    ram_ceiling_gb: u32,
    disk_ceiling_gb: u32,
) -> (Fit, Option<String>) {
    if cost_ram > ram_ceiling_gb {
        return (
            Fit::Unsupported,
            Some(format!(
                "needs {} GB of RAM; this machine has {} GB available for models",
                cost_ram, ram_ceiling_gb
            )),
        );
    }
    if cost_disk > disk_ceiling_gb {
        return (
            Fit::Unsupported,
            Some(format!(
                "needs {} GB to download; {} GB of disk is available",
                cost_disk, disk_ceiling_gb
            )),
        );
    }
    if cost_ram > headroom_ram {
        return (
            Fit::Blocked,
            Some(format!(
                "needs {} GB of RAM; {} GB left after your current selection",
                cost_ram, headroom_ram
            )),
        );
    }
    if cost_disk > headroom_disk {
        return (
            Fit::Blocked,
            Some(format!(
                "needs {} GB to download; {} GB of disk left after your current selection and storage pledge",
                cost_disk, headroom_disk
            )),
        );
    }
    (Fit::Fits, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_has_a_floor_and_scales() {
        assert_eq!(system_reserve_gb(4), 2);
        assert_eq!(system_reserve_gb(8), 2);
        assert_eq!(system_reserve_gb(64), 16);
    }

    #[test]
    fn gb_conversion_rounds_up() {
        const GB: u64 = 1024 * 1024 * 1024;
        assert_eq!(bytes_to_gb_ceil(0), 0);
        assert_eq!(bytes_to_gb_ceil(1), 1);
        assert_eq!(bytes_to_gb_ceil(GB), 1);
        assert_eq!(bytes_to_gb_ceil(GB + 1), 2);
    }

    #[test]
    fn oversized_model_is_unsupported_not_blocked() {
        let (fit, reason) = classify(64, 1, 64, 100, 8, 100);
        assert_eq!(fit, Fit::Unsupported);
        assert!(reason.unwrap().contains("this machine has"));
    }

    #[test]
    fn model_that_fits_alone_but_not_alongside_is_blocked() {
        let (fit, reason) = classify(6, 1, 2, 100, 8, 100);
        assert_eq!(fit, Fit::Blocked);
        assert!(reason.unwrap().contains("current selection"));
    }

    #[test]
    fn disk_pressure_blocks_separately_from_ram() {
        let (fit, reason) = classify(1, 40, 8, 10, 8, 100);
        assert_eq!(fit, Fit::Blocked);
        assert!(reason.unwrap().contains("disk"));
    }

    #[test]
    fn within_both_budgets_fits() {
        let (fit, reason) = classify(4, 5, 8, 100, 8, 100);
        assert_eq!(fit, Fit::Fits);
        assert!(reason.is_none());
    }
}
