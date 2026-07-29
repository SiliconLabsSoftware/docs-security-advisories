import os
import json
import re

advisories = []

for file in os.listdir("Advisories"):

    advisory = None
    title = None
    flags = None
    product = None
    version = None
    cve_id = None
    cve_url = None

    path = os.path.join("Advisories", file)

    with open(path, encoding="utf-8") as f:
        content = f.read()

        lines = [line.strip() for line in content.splitlines()]

        grouped = {}  # key: (product, cve) → accumulated data

        for i, line in enumerate(lines): 
            if re.match(r"# Silicon Labs Security Advisory.*", line):
                match = re.search(r"\bA-\d{8}\b", line)
                advisory = match.group(0) if match else None

                match = re.search(r"A-\d{8}\s*:\s*(.+)", line)
                title = match.group(1).strip() if match else None

            if re.match(r"Flags:.*", line):
                match = re.search(r"Flags:\s*(.+)", line)
                flags = match.group(1).strip() if match else None

            if re.match(r"\|\s*Product\s*\|\s*Impacted Version\s*\|\s*CVE\s*\|", line):
                row_index = i + 2

                while row_index < len(lines) and lines[row_index].startswith("|"):
                    row = lines[row_index]
                    cells = [cell.strip() for cell in row.strip("|").split("|")]

                    if len(cells) >= 3:
                        product = cells[0]
                        version = cells[1]
                        cve_cell = cells[2]

                        cve_match = re.search(
                            r"\[(CVE-\d{4}-\d+)\]\((https?://[^)]+)\)",
                            cve_cell
                        )

                        if cve_match:
                            cve_id = cve_match.group(1)
                            cve_url = cve_match.group(2)
                        else:
                            cve_id = cve_cell
                            cve_url = None

                        key = (product, cve_id)

                        if key not in grouped:
                            grouped[key] = {
                                "product": product,
                                "versions": [],
                                "cve": cve_id,
                                "cve_url": cve_url
                            }

                        grouped[key]["versions"].append(version)

                    row_index += 1

        # Convert grouped data into final advisories list
        for entry in grouped.values():
            advisories.append({
                "advisory": advisory,
                "flags": flags,
                "title": title,
                "product": entry["product"],
                "version": ", ".join(entry["versions"]),
                "cve": entry["cve"],
                "cve_url": entry["cve_url"]
            })


with open("docs/dashboard.json", "w", encoding="utf-8") as f:
    json.dump(advisories, f, indent=2)
