"""Metadata Stripper: removes all EXIF, GPS, camera, and device fingerprints."""
from __future__ import annotations

import pathlib
from typing import Union
from PIL import Image

from app.privacy.file_guard import FileGuard


def strip_metadata(img: Image.Image) -> Image.Image:
    """Create a pristine copy containing only the raw pixel data and no EXIF, GPS, or device tags."""
    # Create fresh image with identical mode and dimensions
    clean = Image.new(img.mode, img.size)
    clean.paste(img)
    # Clear any residual info metadata dict
    clean.info = {}
    return clean


def strip_metadata_from_file(
    input_path: Union[str, pathlib.Path],
    output_path: Union[str, pathlib.Path],
) -> pathlib.Path:
    """Read an image file, strip all EXIF and GPS metadata, and save to a safe output path.

    Guarantees the input file is never overwritten.
    """
    in_path = pathlib.Path(input_path).resolve()
    guard = FileGuard(in_path)
    out_path = guard.validate_destination_path(output_path)

    with Image.open(in_path) as img:
        clean = strip_metadata(img)
        # Determine format from extension or fallback to JPEG/PNG
        ext = out_path.suffix.lower().lstrip(".")
        format_map = {
            "jpg": "JPEG",
            "jpeg": "JPEG",
            "png": "PNG",
            "webp": "WEBP",
            "tiff": "TIFF",
        }
        img_format = format_map.get(ext, img.format or "PNG")
        
        # Save without any EXIF bytes or metadata
        clean.save(out_path, format=img_format)

    # Verify input file remained unchanged
    guard.verify_unmodified()
    return out_path
