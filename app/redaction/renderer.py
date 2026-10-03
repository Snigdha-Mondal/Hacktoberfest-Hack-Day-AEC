"""Visual Redaction Renderer: Solid Blackout, Gaussian Blur, Pixelation, and Crop."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from PIL import Image, ImageDraw, ImageFilter

from app.model.schemas import BoundingBox, Finding, RecommendedAction


class RedactionRenderer:
    """Non-destructive image redaction engine for visual privacy protection."""

    def blackout(
        self,
        img: Image.Image,
        box: BoundingBox,
        color: Tuple[int, int, int] = (0, 0, 0),
    ) -> Image.Image:
        """Apply 100% solid blackout over the bounding box to permanently destroy sensitive data."""
        out = img.copy()
        draw = ImageDraw.Draw(out)
        draw.rectangle([box.x, box.y, box.x2, box.y2], fill=color)
        return out

    def blur(
        self,
        img: Image.Image,
        box: BoundingBox,
        radius: int = 15,
    ) -> Image.Image:
        """Apply strong Gaussian blur to obscure visual identifiers (e.g. faces)."""
        out = img.copy()
        # Crop the region to blur
        crop_box = (box.x, box.y, box.x2, box.y2)
        region = out.crop(crop_box)
        # Apply Gaussian blur
        blurred_region = region.filter(ImageFilter.GaussianBlur(radius=radius))
        out.paste(blurred_region, crop_box)
        return out

    def pixelate(
        self,
        img: Image.Image,
        box: BoundingBox,
        pixel_size: int = 8,
    ) -> Image.Image:
        """Downsample and upsample the region to create a mosaic pixelation effect."""
        out = img.copy()
        crop_box = (box.x, box.y, box.x2, box.y2)
        region = out.crop(crop_box)

        w, h = region.size
        if w <= 0 or h <= 0:
            return out

        # Downsample
        small_w = max(1, w // pixel_size)
        small_h = max(1, h // pixel_size)
        small_region = region.resize((small_w, small_h), resample=Image.Resampling.BILINEAR)

        # Upscale back to original size with nearest neighbor for sharp blocky pixels
        pixelated = small_region.resize((w, h), resample=Image.Resampling.NEAREST)
        out.paste(pixelated, crop_box)
        return out

    def crop(
        self,
        img: Image.Image,
        box: BoundingBox,
    ) -> Image.Image:
        """Crop the image to the specified bounding box."""
        return img.crop((box.x, box.y, box.x2, box.y2))

    def apply_action(
        self,
        img: Image.Image,
        box: BoundingBox,
        action: RecommendedAction,
        **kwargs,
    ) -> Image.Image:
        """Dispatch a single redaction action on a bounding box."""
        if action == RecommendedAction.BLACKOUT:
            color = kwargs.get("color", (0, 0, 0))
            return self.blackout(img, box, color=color)
        elif action == RecommendedAction.BLUR:
            radius = kwargs.get("radius", 15)
            return self.blur(img, box, radius=radius)
        elif action == RecommendedAction.PIXELATE:
            pixel_size = kwargs.get("pixel_size", 8)
            return self.pixelate(img, box, pixel_size=pixel_size)
        elif action == RecommendedAction.CROP:
            return self.crop(img, box)
        elif action in (RecommendedAction.REVIEW, RecommendedAction.NONE):
            return img.copy()
        else:
            return self.blackout(img, box)

    def apply_findings(
        self,
        img: Image.Image,
        findings: List[Finding],
        action_overrides: Optional[Dict[int, RecommendedAction]] = None,
    ) -> Image.Image:
        """Apply visual redactions for all findings that include a BoundingBox.

        Returns a newly allocated Image without mutating the input image.
        """
        current = img.copy()
        overrides = action_overrides or {}

        for idx, f in enumerate(findings):
            if f.location is None:
                continue

            action = overrides.get(idx, f.recommended_action)
            current = self.apply_action(current, f.location, action)

        return current
