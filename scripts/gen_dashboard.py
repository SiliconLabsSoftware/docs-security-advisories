import json
import os
import re

ADVISORIES_DIR = "Advisories"
OUTPUT_PATH = "docs/dashboard.json"


def parse_cves(cve_cell):
    """Return all CVE identifiers and their URLs from a Markdown table cell."""
    results = []
    seen = set()

    # First capture Markdown-linked CVEs so their URLs are retained.
    for match in re.finditer(
        r"\[(CVE-\d{4}-\d+)\]\((https?://[^)]+)\)",
        cve_cell,
        re.IGNORECASE,
    ):
        cve_id = match.group(1).upper()
        if cve_id not in seen:
            results.append((cve_id, match.group(2)))
            seen.add(cve_id)

    # Then capture any additional plain-text CVEs in the same cell.
    for match in re.finditer(r"\bCVE-\d{4}-\d+\b", cve_cell, re.IGNORECASE):
        cve_id = match.group(0).upper()
        if cve_id not in seen:
            results.append((cve_id, None))
            seen.add(cve_id)

    # Preserve the previous behavior for a non-empty cell with no recognizable CVE.
    if not results and cve_cell.strip():
        results.append((cve_cell.strip(), None))

    return results


def parse_markdown_row(line):
    """Split a Markdown table row into stripped cell values."""
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_advisory(path):
    advisory = None
    title = None
    flags = None
    cvss_severity = None
    cvss_string = None
    release_date = None

    with open(path, encoding="utf-8") as f:
        lines = [line.strip() for line in f.read().splitlines()]

    # Find the first date in YYYY-MMM-DD format, e.g. 2025-JAN-27.
    date_match = re.search(
        r"\b\d{4}-(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)-\d{2}\b",
        "\n".join(lines),
        re.IGNORECASE,
    )
    if date_match:
        month_numbers = {
            "JAN": "01", "FEB": "02", "MAR": "03", "APR": "04",
            "MAY": "05", "JUN": "06", "JUL": "07", "AUG": "08",
            "SEP": "09", "OCT": "10", "NOV": "11", "DEC": "12",
        }
        year, month, day = date_match.group(0).upper().split("-")
        release_date = f"{year}-{month_numbers[month]}-{day}"

    results = []

    for i, line in enumerate(lines):
        if re.match(r"# Silicon Labs Security Advisory.*", line):
            match = re.search(r"\bA-\d{8}\b", line)
            advisory = match.group(0) if match else None

            match = re.search(r"A-\d{8}\s*:\s*(.+)", line)
            title = match.group(1).strip() if match else None

        elif line.startswith("Flags:"):
            flags = line.partition(":")[2].strip() or None

        elif line.startswith("CVSS Severity:"):
            cvss_severity = line.partition(":")[2].strip() or None

        elif line.startswith("CVSS String:"):
            cvss_string = line.partition(":")[2].strip() or None

        # Supported Product Impact table formats:
        #   Product | Impacted Version | CVE
        #   Product | Impacted Version | Main SDK | Impacted Version | CVE
        if re.match(r"\|\s*Product\s*\|", line, re.IGNORECASE):
            headers = parse_markdown_row(line)
            normalized_headers = [header.casefold() for header in headers]

            if normalized_headers not in (
                ["product", "impacted version", "cve"],
                [
                    "product",
                    "impacted version",
                    "main sdk",
                    "impacted version",
                    "cve",
                ],
            ):
                continue

            row_index = i + 2  # Skip the Markdown separator row.

            while row_index < len(lines) and lines[row_index].startswith("|"):
                cells = parse_markdown_row(lines[row_index])

                if len(cells) >= len(headers):
                    product = cells[0]
                    version = cells[1]

                    if len(headers) == 5:
                        main_sdk = cells[2] or None
                        main_sdk_impacted_version = cells[3] or None
                        cve_cell = cells[4]
                    else:
                        main_sdk = None
                        main_sdk_impacted_version = None
                        cve_cell = cells[2]

                    cves = parse_cves(cve_cell)
                    cve_ids = ", ".join(cve_id for cve_id, _ in cves)
                    cve_urls = ", ".join(
                        cve_url for _, cve_url in cves if cve_url
                    ) or None

                    results.append(
                        {
                            "advisory": advisory,
                            "release_date": release_date,
                            "flags": flags,
                            "title": title,
                            "cvss_severity": cvss_severity,
                            "cvss_string": cvss_string,
                            "product": product,
                            "version": version,
                            "main_sdk": main_sdk,
                            "main_sdk_impacted_version": main_sdk_impacted_version,
                            "cve": cve_ids,
                            "cve_url": cve_urls,
                        }
                    )

                row_index += 1

    return results

def main():
    advisories = []
    advisory_paths = []

    for root, dirs, files in os.walk(ADVISORIES_DIR):
        for filename in files:
            if filename.lower().endswith(".md"):
                advisory_paths.append(os.path.join(root, filename))

    for path in sorted(advisory_paths, reverse=False):
        advisories.extend(parse_advisory(path))

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(advisories, f, indent=2)


if __name__ == "__main__":
    main()