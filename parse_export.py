#!/usr/bin/env python3
"""Parse Confluence export data and build a US court jurisdiction dictionary."""

import argparse
from html import unescape as html_unescape
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: beautifulsoup4 is required. Install with: pip install beautifulsoup4")
    sys.exit(1)


def find_file(folder: Path, suffix: str) -> Path | None:
    """Find a file in folder ending with the given suffix."""
    for f in folder.iterdir():
        if f.name.endswith(suffix):
            return f
    return None


def parse_main(filepath: Path) -> dict:
    """Extract title, state, county/city, court_name, status from main HTML."""
    html = filepath.read_text(encoding="utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")

    result = {"court_name": None, "state": None, "county": None, "status": None}

    # Find all <th> elements and look for Title / Document Status
    # Some pages use "Title:" with colon, others just "Title"
    for th in soup.find_all("th"):
        th_text = th.get_text(strip=True)

        if th_text in ("Title:", "Title"):
            td = th.find_next_sibling("td")
            if td:
                title = td.get_text(strip=True)
                result["court_name"] = title
                # Try "ST - Name" pattern (e.g. "OH - Cuyahoga")
                m = re.match(r"^([A-Z]{2})\s*[-–—]\s*(.+)$", title)
                if not m:
                    # Try "ID - ST - Name" (e.g. "12126 - FL - Gadsden County")
                    m = re.match(r"^\d+\s*[-–—]\s*([A-Z]{2})\s*[-–—]\s*(.+)$", title)
                if not m:
                    # Try SOR patterns: "SOR - XX/ Name" or "SOR-XX / Name"
                    m = re.match(
                        r"^SOR\s*[-–—]\s*([A-Z]{2})\s*[/]\s*(.+)$", title
                    )
                if not m:
                    # "SOR/XX - Name" (e.g. "SOR/MO - MO- Sex Offender Registry")
                    m = re.match(r"^SOR/([A-Z]{2})\s*[-–—]\s*(.+)$", title)
                if m:
                    result["state"] = m.group(1)
                    result["county"] = m.group(2).strip()

        elif th_text in ("Document Status:", "Document Status"):
            td = th.find_next_sibling("td")
            if td:
                # Status is in <ac:parameter ac:name="title">VALUE</ac:parameter>
                # inside an ac:structured-macro with ac:name="status"
                status_macro = td.find(
                    "ac:structured-macro", attrs={"ac:name": "status"}
                )
                if status_macro:
                    title_param = status_macro.find(
                        "ac:parameter", attrs={"ac:name": "title"}
                    )
                    if title_param:
                        result["status"] = title_param.get_text(strip=True)

    return result


def extract_url_from_sql_value(raw: str) -> str | None:
    """Extract a clean URL from a SQL parameter value that may contain HTML tags."""
    # If it contains an <a href="..."> tag, parse it out
    m = re.search(r'href=["\']([^"\']+)["\']', raw)
    if m:
        return html_unescape(m.group(1))
    # Otherwise use the raw value if it looks like a URL
    raw = raw.strip()
    if raw.startswith("http"):
        return html_unescape(raw)
    return None


def parse_detailed_requirements(filepath: Path) -> str | None:
    """Extract site URL from SQL @sStartURL or @sRootURL in detailed-requirements HTML."""
    html = filepath.read_text(encoding="utf-8", errors="replace")

    for param in ("@sStartURL", "@sRootURL"):
        m = re.search(re.escape(param) + r"='([^']+)'", html)
        if m:
            url = extract_url_from_sql_value(m.group(1))
            if url:
                return url

    return None


def parse_site_navigation(filepath: Path) -> str | None:
    """Extract first URL from site-navigation HTML."""
    html = filepath.read_text(encoding="utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")

    # First <a href="..."> in the content (usually in first <li>)
    a_tag = soup.find("a", href=True)
    if a_tag:
        url = html_unescape(a_tag["href"])
        # Only return actual http URLs, not anchors or confluence links
        if url.startswith("http"):
            return url

    return None


def parse_jurisdiction(folder: Path) -> dict | None:
    """Parse a single jurisdiction folder and return its data."""
    jid = folder.name

    # Main file is always {id}-main.html
    main_file = folder / f"{jid}-main.html"
    if not main_file.exists():
        print(f"  WARN: {jid} — missing main.html, skipping")
        return None

    data = parse_main(main_file)
    data["jurisdiction_id"] = jid

    # Find detailed-requirements and site-navigation files (variable prefix)
    detail_file = find_file(folder, "-detailed-requirements.html")
    nav_file = find_file(folder, "-site-navigation.html")

    # Extract URL: prefer detailed-requirements SQL, fall back to site-navigation
    url = None
    if detail_file:
        url = parse_detailed_requirements(detail_file)
    if not url and nav_file:
        url = parse_site_navigation(nav_file)
    data["site_url"] = url

    return data


def build_dictionary(export_path: str) -> dict:
    """Parse all jurisdiction folders and build grouped dictionary."""
    export_dir = Path(export_path)
    if not export_dir.is_dir():
        print(f"ERROR: Export directory not found: {export_dir}")
        sys.exit(1)

    # Collect all jurisdiction folders (numeric names)
    folders = sorted(
        [d for d in export_dir.iterdir() if d.is_dir() and d.name.isdigit()],
        key=lambda d: int(d.name),
    )
    print(f"Found {len(folders)} jurisdiction folders\n")

    jurisdictions = []
    for folder in folders:
        entry = parse_jurisdiction(folder)
        if entry:
            jurisdictions.append(entry)

    # Group by state, sort states and courts alphabetically
    by_state = defaultdict(list)
    no_state = []
    for j in jurisdictions:
        state = j.get("state")
        if state:
            by_state[state].append(j)
        else:
            no_state.append(j)

    result = {}
    for state in sorted(by_state.keys()):
        result[state] = sorted(by_state[state], key=lambda x: x.get("county") or "")
    if no_state:
        result["_UNKNOWN"] = sorted(no_state, key=lambda x: x.get("court_name") or "")

    return result


def print_stats(grouped: dict):
    """Print summary statistics."""
    total = sum(len(courts) for courts in grouped.values())
    with_url = sum(
        1 for courts in grouped.values() for c in courts if c.get("site_url")
    )
    missing_url = total - with_url

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total jurisdictions: {total}")
    print(f"With site URL:       {with_url}")
    print(f"Missing site URL:    {missing_url}")
    print(f"States:              {len([s for s in grouped if s != '_UNKNOWN'])}")
    print()
    print("Jurisdictions per state:")
    print("-" * 40)
    for state, courts in sorted(grouped.items()):
        urls = sum(1 for c in courts if c.get("site_url"))
        label = f"  {state}"
        print(f"{label:<8} {len(courts):>4} courts  ({urls} with URL)")


def main():
    parser = argparse.ArgumentParser(
        description="Parse Confluence export and build court jurisdiction dictionary"
    )
    parser.add_argument(
        "export_path",
        nargs="?",
        default="../conf2/export",
        help="Path to export directory (default: ../conf2/export)",
    )
    parser.add_argument(
        "-o", "--output",
        default="courts.json",
        help="Output JSON file (default: courts.json)",
    )
    args = parser.parse_args()

    grouped = build_dictionary(args.export_path)

    # Write JSON
    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(grouped, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {output_path}")
    print()

    print_stats(grouped)


if __name__ == "__main__":
    main()
