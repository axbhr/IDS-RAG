import os
import re
import yaml
import requests
import click
from typing import List, Dict, Any

# MITRE ATT&CK Enterprise STIX JSON (official MITRE CTI GitHub)
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# OWASP Top 10 2021 - official OWASP GitHub repository
OWASP_GITHUB_CONTENTS_URL = (
    "https://api.github.com/repos/OWASP/Top10/contents/2021/docs/en"
)
OWASP_RAW_BASE_URL = (
    "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en"
)

# Top 10 MITRE ATT&CK technique IDs - most prevalent in threat intelligence reports
TOP_10_TECHNIQUE_IDS = [
    "T1059",  # Command and Scripting Interpreter
    "T1078",  # Valid Accounts
    "T1190",  # Exploit Public-Facing Application
    "T1133",  # External Remote Services
    "T1566",  # Phishing
    "T1486",  # Data Encrypted for Impact (Ransomware)
    "T1027",  # Obfuscated Files or Information
    "T1562",  # Impair Defenses
    "T1055",  # Process Injection
    "T1071",  # Application Layer Protocol
]

# Filename pattern for the actual Top-10 entries (A01-A10), excluding appendices
_OWASP_FILE_RE = re.compile(r"^A(0[1-9]|10)_2021-.*\.md$")


# -----------------------------------------------------------------------
# MITRE ATT&CK helpers
# -----------------------------------------------------------------------

def _extract_technique_id(stix_object: Dict) -> str:
    for ref in stix_object.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _clean_content(text: str) -> str:
    """Strips common noise from MITRE and OWASP text before RAG ingestion.

    Handles both sources safely – rules that don't apply to a given source
    are simply no-ops (e.g. Jekyll attributes never appear in MITRE text).

    Removed:
    - MITRE citation markers:        (Citation: SomeName)
    - Jekyll/Kramdown attributes:    {: style="..." align="..."}
    - Markdown image tags:           ![alt](url)
    - OWASP statistics section:      ## Factors  (table with incidence rates)
    - OWASP CWE link list:           ## List of Mapped CWEs
    - URLs in markdown links:        [label](url) -> label
    - Trailing whitespace per line
    - Excessive blank lines (3+ -> 1)
    """
    # 1. MITRE: remove citation markers, e.g. (Citation: Powershell Remote Commands)
    text = re.sub(r"\(Citation:[^)]+\)", "", text)

    # 2. MITRE: strip HTML tags, e.g. <code>Start-Process</code> -> Start-Process
    text = re.sub(r"<[^>]+>", "", text)

    # 2. OWASP: remove Jekyll inline attributes, e.g. {: style="height:80px" align="right"}
    text = re.sub(r"\{:[^}]*\}", "", text)

    # 3. OWASP: remove markdown image tags, e.g. ![icon](assets/foo.png)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)

    # 4. OWASP: drop the entire "## Factors" section (statistics table)
    text = re.sub(r"## Factors\s*\n.*?(?=\n## |\Z)", "", text, flags=re.DOTALL)

    # 5. OWASP: drop the "## List of Mapped CWEs" section (just hyperlinks)
    text = re.sub(r"## List of Mapped CWEs\s*\n.*?(?=\n## |\Z)", "", text, flags=re.DOTALL)

    # 6. Convert remaining markdown links to plain text: [label](url) -> label
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)

    # 7. Strip trailing whitespace on each line
    text = "\n".join(line.rstrip() for line in text.splitlines())

    # 9. Collapse multiple inline spaces (left by removed markers) into one
    text = re.sub(r"[ \t]{2,}", " ", text)

    # 10. Remove bare URLs left on their own line (no semantic value for embeddings)
    text = re.sub(r"^https?://\S+$", "", text, flags=re.MULTILINE)

    # 11. Collapse more than two consecutive blank lines into one
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def _parse_mitre_technique(
    obj: Dict, sub_techniques: List[Dict[str, str]] | None = None
) -> Dict[str, Any]:
    """Builds a RAG document from a MITRE ATT&CK STIX attack-pattern object.

    Args:
        obj: The STIX attack-pattern object for the parent technique.
        sub_techniques: Optional list of {"id": "T1059.001", "name": "...",
            "description": "...", "detection": "..."} dicts from its
            sub-techniques. Descriptions are always included; detection only
            when non-empty.
    """
    technique_id = _extract_technique_id(obj)
    name = obj.get("name", "Unknown Technique")
    description = _clean_content(obj.get("description", "No description available."))
    raw_detection = obj.get("x_mitre_detection", "").strip()
    detection = _clean_content(raw_detection) if raw_detection else None
    platforms = ", ".join(obj.get("x_mitre_platforms", [])) or "Unknown"
    tactics = ", ".join(
        phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])
    )
    url = next(
        (
            ref.get("url", "")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ),
        "",
    )

    # Reference URL belongs only in metadata – not useful for semantic search
    lines = [
        f"MITRE ATT&CK Technique: {technique_id} - {name}",
        f"Tactics: {tactics}",
        f"Platforms: {platforms}",
        "",
        "Description:",
        description,
    ]

    # Parent-level detection (present in older ATT&CK versions)
    if detection:
        lines += ["", "Detection Guidance:", detection]

    # Sub-techniques: descriptions enrich semantic search even when detection is empty
    if sub_techniques:
        lines += ["", "Sub-Techniques:"]
        for sub in sub_techniques:
            sub_desc = _clean_content(sub.get("description", ""))
            sub_det = _clean_content(sub.get("detection", ""))
            if sub_desc:
                lines += ["", f"{sub['id']} - {sub['name']}:", sub_desc]
                if sub_det:
                    lines += ["", "Detection:", sub_det]

    content = "\n".join(lines) + "\n"
    return {
        "type": "text",
        "content": content,
        "metadata": {
            "source": "mitre_attack",
            "technique_id": technique_id,
            "name": name,
            "tactics": tactics,
            "url": url,
        },
    }


def sync_mitre_attack(output_file: str) -> bool:
    click.echo("Downloading MITRE ATT&CK Enterprise data from GitHub...")
    try:
        response = requests.get(MITRE_ATTACK_URL, timeout=60)
        response.raise_for_status()
    except Exception as e:
        click.echo(f"Error downloading MITRE ATT&CK data: {e}")
        return False

    click.echo("Download complete. Extracting Top 10 techniques...")
    try:
        stix_bundle = response.json()
    except Exception as e:
        click.echo(f"Error parsing MITRE ATT&CK JSON: {e}")
        return False

    # First pass: collect all valid attack-pattern objects
    parent_objs: Dict[str, Dict] = {}   # e.g. "T1059"  -> stix obj
    sub_objs: Dict[str, List[Dict]] = {}  # e.g. "T1059" -> [T1059.001 stix obj, ...]

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _extract_technique_id(obj)
        if not tid:
            continue

        if "." in tid:
            # Sub-technique: belongs to parent T-ID before the dot
            parent_tid = tid.split(".")[0]
            if parent_tid in TOP_10_TECHNIQUE_IDS:
                sub_objs.setdefault(parent_tid, []).append(obj)
        elif tid in TOP_10_TECHNIQUE_IDS:
            parent_objs[tid] = obj

    # Second pass: build documents, attaching sub-technique detections
    lookup: Dict[str, Dict] = {}
    for tid, obj in parent_objs.items():
        subs = sub_objs.get(tid, [])
        # Sort sub-techniques by ID for deterministic output
        subs.sort(key=lambda o: _extract_technique_id(o))
        sub_techniques = [
            {
                "id": _extract_technique_id(s),
                "name": s.get("name", ""),
                "description": s.get("description", "").strip(),
                "detection": s.get("x_mitre_detection", "").strip(),
            }
            for s in subs
            if s.get("description", "").strip()
        ]
        lookup[tid] = _parse_mitre_technique(obj, sub_techniques or None)
        click.echo(f"  {tid}: +{len(sub_techniques)} sub-technique(s)")

    documents = [lookup[tid] for tid in TOP_10_TECHNIQUE_IDS if tid in lookup]
    click.echo(f"Extracted {len(documents)}/{len(TOP_10_TECHNIQUE_IDS)} MITRE ATT&CK techniques.")

    if not documents:
        click.echo("No MITRE ATT&CK techniques found.")
        return False

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        yaml.dump({"documents": documents}, f, sort_keys=False, allow_unicode=True)

    click.echo(f"Created MITRE ATT&CK knowledge file at: {output_file}")
    return True


# -----------------------------------------------------------------------
# OWASP Top 10 helpers
# -----------------------------------------------------------------------

def _parse_owasp_markdown(filename: str, raw_markdown: str) -> Dict[str, Any]:
    owasp_id = re.sub(r"^(A\d{2})_(\d{4})-.*\.md$", r"\1:\2", filename)
    cleaned = _clean_content(raw_markdown)
    title_match = re.search(r"^#\s+(.+)$", cleaned, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else filename
    return {
        "type": "text",
        "content": cleaned,
        "metadata": {
            "source": "owasp_top10_2021",
            "owasp_id": owasp_id,
            "name": title,
            "file": filename,
        },
    }


def sync_owasp_top10(output_file: str) -> bool:
    click.echo("Fetching OWASP Top 10 (2021) file list from GitHub...")
    try:
        resp = requests.get(OWASP_GITHUB_CONTENTS_URL, timeout=30)
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        click.echo(f"Error fetching OWASP file list: {e}")
        return False

    files = sorted(
        [e for e in entries if isinstance(e, dict) and _OWASP_FILE_RE.match(e.get("name", ""))],
        key=lambda e: e["name"],
    )

    if not files:
        click.echo("No OWASP Top 10 files found in the repository.")
        return False

    click.echo(f"Found {len(files)} OWASP files. Downloading...")
    documents = []
    for entry in files:
        filename = entry["name"]
        download_url = f"{OWASP_RAW_BASE_URL}/{filename}"
        try:
            r = requests.get(download_url, timeout=15)
            r.raise_for_status()
            doc = _parse_owasp_markdown(filename, r.text)
            documents.append(doc)
            click.echo(f"  + {filename}")
        except Exception as e:
            click.echo(f"  ! Failed to download {filename}: {e}")

    if not documents:
        click.echo("No OWASP documents could be downloaded.")
        return False

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        yaml.dump({"documents": documents}, f, sort_keys=False, allow_unicode=True)

    click.echo(
        f"Created OWASP Top 10 knowledge file at: {output_file} ({len(documents)} entries)"
    )
    return True
