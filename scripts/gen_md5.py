#!/usr/bin/env python3

from pathlib import Path
import hashlib

# Root advisories directory
ADVISORIES_DIR = Path("Advisories")


def md5sum(file_path: Path) -> str:
    """Generate MD5 hash for a file."""
    hash_md5 = hashlib.md5()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


def main():
    markdown_files = list(ADVISORIES_DIR.rglob("*.md"))

    if not markdown_files:
        print("No markdown files found.")
        return

    for md_file in markdown_files:
        digest = md5sum(md_file)

        # Create .md5 file alongside the markdown file
        md5_file = md_file.with_suffix(".md5")

        with md5_file.open("w") as f:
            f.write(f"{digest}  {md_file.name}\n")

        print(f"Generated: {md5_file}")


if __name__ == "__main__":
    main()
