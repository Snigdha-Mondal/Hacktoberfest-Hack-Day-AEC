"""Gemma 4 Vision Adapter Client for local-first multimodal privacy inspection.

Connects to local Ollama (or compatible HTTP API) with offline privacy guarantees,
handling base64 image encoding, prompt injection defense, and graceful degradation.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import List, Optional, Tuple

import httpx
from PIL import Image

from app.model.prompt import (
    build_user_prompt,
    get_system_prompt,
    parse_gemma_response,
)
from app.model.schemas import Finding


class GemmaVisionAdapter:
    """Client adapter for communicating with local Gemma 4 multimodal vision models."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_HOST")
            or "http://localhost:11434"
        ).rstrip("/")
        self.model = (
            model
            or os.environ.get("SAFEDROP_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or "gemma4:e4b"
        )
        self.timeout = float(timeout)

    def _encode_image(self, image_path: str | Path) -> Tuple[str, int, int]:
        """Verify image, get pixel dimensions, and return base64 encoded string."""
        path = Path(image_path)
        with Image.open(path) as img:
            width, height = img.size

        with open(path, "rb") as f:
            b64_str = base64.b64encode(f.read()).decode("utf-8")

        return b64_str, width, height

    def analyze_image(
        self,
        image_path: str | Path,
        context_hint: str = "",
        language: str = "en",
    ) -> Tuple[List[Finding], List[str], str]:
        """Analyze an image using Gemma 4 multimodal model.

        Returns:
            (findings, uncertainty_flags, summary)
        """
        path = Path(image_path)
        if not path.is_file():
            return (
                [],
                [f"File not found: {str(image_path)}"],
                "File does not exist or cannot be accessed.",
            )

        try:
            b64_img, img_width, img_height = self._encode_image(path)
        except Exception as e:
            return (
                [],
                [f"Failed to read or decode image '{path.name}': {str(e)}"],
                "Corrupted or invalid image file.",
            )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": get_system_prompt(language)},
                {
                    "role": "user",
                    "content": build_user_prompt(context_hint, language),
                    "images": [b64_img],
                },
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
            },
        }

        url = f"{self.base_url}/api/chat"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, json=payload)

            if response.status_code != 200:
                return (
                    [],
                    [f"Ollama returned HTTP {response.status_code}: {response.text[:200]}"],
                    f"Gemma 4 model service responded with error status {response.status_code}.",
                )

            data = response.json()
            message_content = data.get("message", {}).get("content", "")

            findings, flags, summary = parse_gemma_response(
                message_content, img_width=img_width, img_height=img_height
            )
            return (findings, flags, summary)

        except httpx.ConnectError:
            return (
                [],
                [
                    f"Ollama connection failed: Unable to connect to local service at {self.base_url}. "
                    "Make sure Ollama is running (`ollama serve`)."
                ],
                "Gemma 4 visual analysis unavailable (offline/service unreachable).",
            )
        except httpx.TimeoutException:
            return (
                [],
                [f"Ollama request timed out after {self.timeout}s on model '{self.model}'."],
                "Gemma 4 visual analysis timed out.",
            )
        except Exception as e:
            return (
                [],
                [f"Unexpected error communicating with Gemma 4: {str(e)}"],
                "Visual analysis encountered an unexpected error.",
            )
