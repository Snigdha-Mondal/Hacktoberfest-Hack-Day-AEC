"""FileGuard utility for guaranteeing input file immutability and safe export paths."""
import hashlib
import os
import pathlib
from typing import Union


class FileOverwriteError(Exception):
    """Raised when an operation attempts to overwrite or mutate an original input file."""
    pass


def compute_file_hash(target: Union[str, bytes, pathlib.Path]) -> str:
    """Compute standard SHA-256 hex digest of a file path or raw bytes."""
    hasher = hashlib.sha256()

    if isinstance(target, bytes):
        hasher.update(target)
        return hasher.hexdigest()

    path = pathlib.Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for hashing: {target}")

    with open(path, "rb") as f:
        # Read in 64KB chunks to efficiently handle large files
        while chunk := f.read(65536):
            hasher.update(chunk)

    return hasher.hexdigest()


class FileGuard:
    """Guards an input file, records its baseline cryptographic hash, and prevents overwriting."""

    def __init__(self, original_path: Union[str, pathlib.Path]):
        self.original_path = pathlib.Path(original_path).resolve()
        if not self.original_path.exists():
            raise FileNotFoundError(f"Target file does not exist: {self.original_path}")

        # Record baseline cryptographic integrity hash
        self._initial_hash = compute_file_hash(self.original_path)

    @property
    def initial_hash(self) -> str:
        """The baseline SHA-256 hash recorded upon file ingestion."""
        return self._initial_hash

    def verify_unmodified(self) -> bool:
        """Verify that the original file on disk has not been altered in any way.

        Raises:
            FileOverwriteError: If the file hash differs from the initial ingestion hash.
        """
        if not self.original_path.exists():
            raise FileOverwriteError(f"Original file was deleted or moved: {self.original_path}")

        current_hash = compute_file_hash(self.original_path)
        if current_hash != self._initial_hash:
            raise FileOverwriteError(
                f"CRITICAL PRIVACY VIOLATION: Original file has been mutated! "
                f"Initial SHA-256: {self._initial_hash}, Current SHA-256: {current_hash}"
            )
        return True

    def validate_destination_path(self, destination: Union[str, pathlib.Path]) -> pathlib.Path:
        """Validate that a proposed output destination does NOT overwrite the original file."""
        dest_path = pathlib.Path(destination).resolve()
        if dest_path == self.original_path:
            raise FileOverwriteError(
                f"SafeDrop strict policy: Writing directly to original path '{self.original_path}' is forbidden."
            )
        return dest_path

    def generate_safe_output_path(
        self,
        suffix: str = "-safedrop",
        target_dir: Union[str, pathlib.Path, None] = None
    ) -> pathlib.Path:
        """Generate a guaranteed non-destructive output path with the specified suffix.

        Example:
            document.png -> document-safedrop.png
            document-safedrop.png (if exists) -> document-safedrop-1.png
        """
        directory = pathlib.Path(target_dir).resolve() if target_dir else self.original_path.parent
        stem = self.original_path.stem
        ext = self.original_path.suffix

        candidate = directory / f"{stem}{suffix}{ext}"
        if not candidate.exists() and candidate != self.original_path:
            return candidate

        # If candidate already exists on disk, append increment counter
        counter = 1
        while True:
            candidate = directory / f"{stem}{suffix}-{counter}{ext}"
            if not candidate.exists() and candidate != self.original_path:
                return candidate
            counter += 1
