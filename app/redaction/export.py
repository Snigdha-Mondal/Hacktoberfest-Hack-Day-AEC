"""SafeExportPipeline: Orchestrates visual redaction, EXIF stripping, and non-destructive export."""
from __future__ import annotations

import pathlib
from typing import Dict, List, Optional, Union
from pydantic import BaseModel
from PIL import Image

from app.model.schemas import Finding, RecommendedAction
from app.privacy.file_guard import FileGuard, compute_file_hash
from app.redaction.metadata_strip import strip_metadata
from app.redaction.renderer import RedactionRenderer


class ExportResult(BaseModel):
    """Report detailing the sanitized export and cryptographic immutability verification."""
    original_path: pathlib.Path
    exported_path: pathlib.Path
    original_hash: str
    exported_hash: str
    redacted_count: int
    metadata_stripped: bool = True
    immutable_verified: bool = True


class SafeExportPipeline:
    """Non-destructive export pipeline ensuring zero alteration of original files."""

    def __init__(self, renderer: Optional[RedactionRenderer] = None):
        self.renderer = renderer or RedactionRenderer()

    def export(
        self,
        input_path: Union[str, pathlib.Path],
        findings: List[Finding],
        destination_path: Optional[Union[str, pathlib.Path]] = None,
        action_overrides: Optional[Dict[int, RecommendedAction]] = None,
        strip_exif: bool = True,
    ) -> ExportResult:
        """Apply redactions and strip metadata, saving strictly to a non-destructive output path.

        Raises:
            FileOverwriteError: If destination_path points to the original input file.
            FileNotFoundError: If the input_path does not exist.
        """
        source = pathlib.Path(input_path).resolve()
        guard = FileGuard(source)

        # Resolve destination path with zero-overwrite enforcement
        if destination_path is not None:
            dest = guard.validate_destination_path(destination_path)
        else:
            dest = guard.generate_safe_output_path()

        # Ensure parent directory exists
        dest.parent.mkdir(parents=True, exist_ok=True)

        with Image.open(source) as img:
            # 1. Apply visual bounding box redactions
            redacted_img = self.renderer.apply_findings(
                img, findings, action_overrides=action_overrides
            )

            # 2. Strip EXIF, GPS, and device metadata
            if strip_exif:
                clean_img = strip_metadata(redacted_img)
            else:
                clean_img = redacted_img

            # 3. Determine output image format
            ext = dest.suffix.lower().lstrip(".")
            format_map = {
                "jpg": "JPEG",
                "jpeg": "JPEG",
                "png": "PNG",
                "webp": "WEBP",
                "tiff": "TIFF",
            }
            img_format = format_map.get(ext, img.format or "PNG")

            # 4. Save sanitized file to destination (no original touched)
            clean_img.save(dest, format=img_format)

        # 5. Cryptographically verify the original file remains byte-for-byte identical
        guard.verify_unmodified()

        # Count how many findings were visually redacted (not NONE or REVIEW)
        overrides = action_overrides or {}
        redacted_count = sum(
            1
            for idx, f in enumerate(findings)
            if f.location is not None
            and overrides.get(idx, f.recommended_action) not in (RecommendedAction.NONE, RecommendedAction.REVIEW)
        )

        return ExportResult(
            original_path=source,
            exported_path=dest,
            original_hash=guard.initial_hash,
            exported_hash=compute_file_hash(dest),
            redacted_count=redacted_count,
            metadata_stripped=strip_exif,
            immutable_verified=True,
        )
