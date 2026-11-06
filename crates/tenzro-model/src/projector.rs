//! Vision projectors of the vision-language models served on the Praecise
//! engine (rerankers and pooled embedders), and the input they read.
//!
//! Pictures and frames are sized exactly as the checkpoint's own pipeline
//! sizes them ([`crate::vision_input`]) and laid out the way its pipeline
//! lays them out: the video, then the picture, then the text.

use std::path::Path;

#[cfg(feature = "mtmd")]
use llama_cpp_2::model::LlamaModel;

use crate::catalog::VisionPreprocess;
#[cfg(feature = "mtmd")]
use crate::error::{ModelError, Result};
#[cfg(feature = "mtmd")]
use crate::text_embedding_runtime::EmbedInput;

/// A loaded projector and how the checkpoint sizes its pictures.
#[cfg(feature = "mtmd")]
pub struct Projector {
    pub(crate) context: std::sync::Mutex<llama_cpp_2::mtmd::MtmdContext>,
    pub(crate) input: VisionPreprocess,
}

/// The projector file of a vision-language model and the checkpoint's
/// picture sizing, both from the catalog entry.
#[derive(Debug, Clone)]
pub struct ProjectorFile<'a> {
    pub path: &'a Path,
    pub input: &'a VisionPreprocess,
}

#[cfg(feature = "mtmd")]
pub fn load(model_id: &str, model: &LlamaModel, p: ProjectorFile<'_>) -> Result<Projector> {
    use llama_cpp_2::mtmd::{MtmdContext, MtmdContextParams};

    let path = p.path.to_str().ok_or_else(|| {
        ModelError::InvalidModel(format!("{model_id}: projector path is not UTF-8"))
    })?;
    // Pictures arrive already sized by the checkpoint's rule, so the
    // projector's own limits are set to the same bounds and leave them as
    // they are.
    let merged = u64::from(p.input.patch_size * p.input.merge_size).pow(2);
    let tokens = |pixels: u64| i32::try_from(pixels / merged).unwrap_or(i32::MAX);
    let params = MtmdContextParams {
        use_gpu: true,
        n_threads: std::thread::available_parallelism()
            .map(|n| i32::try_from(n.get()).unwrap_or(4))
            .unwrap_or(4),
        image_min_tokens: tokens(p.input.image_min_pixels),
        image_max_tokens: tokens(p.input.image_max_pixels.max(p.input.video_frame_max_pixels)),
        ..MtmdContextParams::default()
    };
    // SAFETY: every holder keeps the projector beside `model` and declares it
    // ahead of the model, so it is dropped first.
    let projector = unsafe { MtmdContext::init_from_file(path, model, &params) }
        .map_err(|e| ModelError::InvalidModel(format!("{model_id} projector: {e}")))?;
    if !projector.support_vision() {
        return Err(ModelError::InvalidModel(format!(
            "{model_id}: the projector has no vision tower"
        )));
    }
    Ok(Projector {
        context: std::sync::Mutex::new(projector),
        input: p.input.clone(),
    })
}

/// One input (a pair side, or an input to embed) as the checkpoint's own
/// pipeline writes it: the video (its frames under per-slice timestamps),
/// then the picture, then the text, each picture standing as `marker` in the
/// text; `NULL` when the side carries nothing. With `wrap_video` the whole
/// video, timestamps included, sits between the vision markers, as the
/// embedder's pipeline writes it; the reranker's does not.
///
/// # Errors
/// [`ModelError::InvalidInput`] when the text contains `marker` or a picture
/// or frame cannot be decoded.
#[cfg(feature = "mtmd")]
pub fn media_input(
    input: &EmbedInput,
    spec: &VisionPreprocess,
    marker: &str,
    wrap_video: bool,
) -> Result<praecise_runtime::media::MediaInput> {
    use crate::vision_input::{VISION_END, VISION_START, prepare_image, prepare_video};
    use praecise_runtime::media::{MediaInput, Picture};

    let picture = |f: &crate::vision_input::RgbImage, video_frame: bool| -> Result<Picture> {
        Ok(Picture {
            width: u32::try_from(f.width)
                .map_err(|_| ModelError::InvalidInput("picture too large".into()))?,
            height: u32::try_from(f.height)
                .map_err(|_| ModelError::InvalidInput("picture too large".into()))?,
            rgb: f.data.clone(),
            video_frame,
        })
    };
    if input.text.as_deref().is_some_and(|t| t.contains(marker)) {
        return Err(ModelError::InvalidInput(format!(
            "text may not contain {marker}"
        )));
    }
    let mut out = MediaInput::default();
    if let Some(frames) = &input.video {
        let video = prepare_video(frames, spec)?;
        // Each slice is its timestamp, then the slice's frames, which the
        // projector merges into one block between its own vision markers.
        let per_slice = spec.temporal_patch_size as usize;
        if wrap_video {
            out.text.push_str(VISION_START);
        }
        for ts in &video.timestamps {
            out.text.push('<');
            out.text.push_str(ts);
            out.text.push_str(" seconds>");
            out.text.push_str(&marker.repeat(per_slice));
        }
        if wrap_video {
            out.text.push_str(VISION_END);
        }
        for f in &video.frames {
            out.pictures.push(picture(f, true)?);
        }
    }
    if let Some(bytes) = &input.image {
        let image = prepare_image(bytes, spec)?;
        out.text.push_str(marker);
        out.pictures.push(picture(&image.frames[0], false)?);
    }
    if let Some(text) = &input.text {
        out.text.push_str(text);
    }
    if out.text.is_empty() {
        out.text.push_str(praecise_runtime::embed::EMPTY_INPUT);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ModelError;

    #[cfg(feature = "mtmd")]
    #[test]
    fn an_input_is_laid_out_as_the_checkpoint_pipeline_lays_it_out() {
        crate::seeded_catalog();
        let spec = crate::catalog::get_rerank_model_by_id("qwen3-vl-reranker-2b")
            .unwrap()
            .vision_input
            .unwrap();
        let empty = media_input(&EmbedInput::default(), &spec, "<m>", false).unwrap();
        assert_eq!(empty.text, "NULL");
        assert!(empty.pictures.is_empty());
        let text = media_input(&EmbedInput::text("a cat"), &spec, "<m>", false).unwrap();
        assert_eq!(text.text, "a cat");
        let refused = media_input(&EmbedInput::text("x <m> y"), &spec, "<m>", false);
        assert!(
            matches!(refused, Err(ModelError::InvalidInput(_))),
            "{refused:?}"
        );
    }

    #[cfg(feature = "mtmd")]
    #[test]
    fn a_wrapped_video_sits_between_the_vision_markers() {
        crate::seeded_catalog();
        let spec = crate::catalog::get_embed_model_by_id("qwen3-vl-embedding-2b")
            .unwrap()
            .vision_input
            .unwrap();
        let mut png = std::io::Cursor::new(Vec::new());
        image::RgbImage::from_pixel(320, 240, image::Rgb([90, 120, 200]))
            .write_to(&mut png, image::ImageFormat::Png)
            .unwrap();
        let input = EmbedInput {
            video: Some(vec![png.into_inner(); 4]),
            ..EmbedInput::default()
        };
        let wrapped = media_input(&input, &spec, "<m>", true).unwrap();
        let bare = media_input(&input, &spec, "<m>", false).unwrap();
        assert!(
            wrapped.text.starts_with("<|vision_start|><")
                && wrapped.text.ends_with("<m><|vision_end|>"),
            "{}",
            wrapped.text
        );
        assert_eq!(
            wrapped.text,
            format!("<|vision_start|>{}<|vision_end|>", bare.text)
        );
        assert_eq!(wrapped.pictures.len(), bare.pictures.len());
    }
}
