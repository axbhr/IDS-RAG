import os
import yaml
import requests
import zipfile
import io
import click
from typing import List, Dict, Optional, Any

# URL for Sigma Repository ZIP (master branch)
SIGMA_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"


def parse_sigma_rule(content: str, filename: str) -> Optional[Dict[str, Any]]:
    """Analyzes a Sigma rule and returns a RAG-compatible document dict, or None if skipped."""
    try:
        documents = list(yaml.safe_load_all(content))
        if not documents:
            return None

        rule = documents[0]
        if not isinstance(rule, dict) or "title" not in rule or "detection" not in rule:
            return None

        # Get logsource info safely
        logsource = rule.get("logsource", {})
        if not isinstance(logsource, dict):
            return None

        category = str(logsource.get("category", "")).lower()
        product = str(logsource.get("product", "")).lower()
        service = str(logsource.get("service", "")).lower()

        # Filter: We want network related rules or generic web attacks
        relevant_categories = [
            "network_connection",
            "proxy",
            "firewall",
            "dns",
            "web_server",
            "intrusion_detection",
        ]
        relevant_services = ["http", "ssh", "dns", "ftp", "smb", "ssl"]
        relevant_products = [
            "zeek",
            "suricata",
            "corelight",
            "f5",
            "checkpoint",
            "paloalto",
        ]

        is_relevant = False

        if category in relevant_categories:
            is_relevant = True
        elif service in relevant_services:
            is_relevant = True
        elif product in relevant_products:
            is_relevant = True
        elif "network" in category or "cve" in rule.get("title", "").lower():
            is_relevant = True

        if not is_relevant:
            return None

        # Extract fields
        title = rule.get("title", "Unknown Rule")
        description = rule.get("description", "No description provided.")
        level = rule.get("level", "unknown")
        tags = rule.get("tags", []) or []

        detection = rule.get("detection", {})
        try:
            detection_str = yaml.dump(detection, default_flow_style=False)
        except:
            detection_str = str(detection)

        content = f"""
Title: {title}
Description: {description}
Severity Level: {level}
Tags: {', '.join(tags) if tags else 'None'}

Detection Logic (Sigma):
{detection_str}
"""

        return {
            "type": "text",
            "content": content,
            "metadata": {
                "source": "sigma_rule",
                "rule_id": str(rule.get("id", "unknown")),
                "category": category or service or product or "network",
                "file": filename,
            },
        }

    except Exception as e:
        return None


def sync_sigma_rules(output_file: str):
    """Downloads Sigma rules and processes them for the RAG system."""
    click.echo(f"Downloading Sigma rules from {SIGMA_ZIP_URL}...")
    try:
        response = requests.get(SIGMA_ZIP_URL)
        response.raise_for_status()
    except Exception as e:
        click.echo(f"Error downloading zip: {e}")
        return False

    click.echo("Download complete. Processing rules in memory...")

    rag_documents = []

    try:
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            for file_info in z.infolist():
                # We filter for yaml files inside a 'rules/' directory
                if (
                    not file_info.is_dir()
                    and "rules/" in file_info.filename
                    and (
                        file_info.filename.endswith(".yml")
                        or file_info.filename.endswith(".yaml")
                    )
                ):

                    with z.open(file_info) as f:
                        try:
                            content = f.read().decode("utf-8")
                            doc = parse_sigma_rule(
                                content, os.path.basename(file_info.filename)
                            )
                            if doc:
                                rag_documents.append(doc)
                        except Exception as e:
                            pass

    except zipfile.BadZipFile:
        click.echo("Error: The downloaded file is not a valid zip archive.")
        return False

    click.echo(f"Successfully extracted {len(rag_documents)} network-relevant rules.")

    if rag_documents:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Use simple dictionary structure
        output_data = {"documents": rag_documents}

        with open(output_file, "w") as f:
            yaml.dump(output_data, f, sort_keys=False)

        click.echo(f"Created RAG import file at: {output_file}")
        return True
    else:
        click.echo("No valid rules found.")
        return False
