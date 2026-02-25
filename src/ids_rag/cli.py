import click
import os
from .rag_system import RAGSystem
from .alert_parser import SuricataAlertParser, SuricataMonitor
from .knowledge_sync import sync_mitre_attack, sync_owasp_top10

# Initialize RAG system with default config location
CONFIG_PATH = os.path.join(os.getcwd(), "config.yaml")


def _load_config(path):
    import yaml

    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f)


@click.group()
def cli():
    """Local RAG System CLI using Ollama."""
    pass


@cli.command()
@click.option(
    "--ingest", "do_ingest", is_flag=True, help="Automatically ingest after syncing."
)
def sync(do_ingest):
    """Download MITRE ATT&CK Top 10 and OWASP Top 10 into the knowledge base."""
    sources = [
        {
            "label": "MITRE ATT&CK Top 10",
            "output": "knowledge_base/mitre_attack_top10.yaml",
            "fn": sync_mitre_attack,
        },
        {
            "label": "OWASP Top 10 (2021)",
            "output": "knowledge_base/owasp_top10.yaml",
            "fn": sync_owasp_top10,
        },
    ]

    synced_files = []
    for source in sources:
        click.echo(f"\n--- Syncing {source['label']} ---")
        if source["fn"](source["output"]):
            synced_files.append(source["output"])
        else:
            click.echo(f"Warning: {source['label']} sync failed.")

    if not synced_files:
        click.echo("\nSync failed for all sources.")
        return

    click.echo(f"\nSync complete. {len(synced_files)}/{len(sources)} sources succeeded.")

    if do_ingest:
        click.echo("\nAuto-ingesting synced files...")
        try:
            rag = RAGSystem(config_path=CONFIG_PATH)
            for f in synced_files:
                click.echo(f"  Ingesting {f}...")
                rag.ingest_from_yaml(f)
        except Exception as e:
            click.echo(f"Error during ingestion: {e}")
    else:
        click.echo("Run 'ids-rag ingest' to load the new rules into the database.")


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
def ingest(files):
    """Ingest data from YAML files. Defaults to 'knowledge_base/' if no file provided."""
    try:
        rag = RAGSystem(config_path=CONFIG_PATH)

        targets = []

        # Determine what to ingest
        if not files:
            # Default: Scan knowledge_base folder
            kb_path = "knowledge_base"
            if os.path.exists(kb_path):
                for f in os.listdir(kb_path):
                    if f.endswith(".yaml") or f.endswith(".yml"):
                        targets.append(os.path.join(kb_path, f))

            # Also check for root data.yaml as a default
            if os.path.exists("data.yaml"):
                targets.append("data.yaml")

            if not targets:
                click.echo(
                    "No input files provided and no YAML files found in 'knowledge_base/' or root."
                )
                return
        else:
            # User provided specific files or folders
            for path in files:
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        if f.endswith(".yaml") or f.endswith(".yml"):
                            targets.append(os.path.join(path, f))
                else:
                    targets.append(path)

        # Process all targets
        for target in targets:
            click.echo(f"Processing {target}...")
            rag.ingest_from_yaml(target)

    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.argument("question")
@click.option(
    "--mode",
    type=click.Choice(["chat", "analyst"]),
    default="chat",
    help="Switch between 'chat' (explanatory) and 'analyst' (strict detection) mode.",
)
@click.option(
    "--top-k",
    type=int,
    default=10,
    help="Number of relevant documents to retrieve (default: 10, use 0 for all).",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug output to see normalized logs.",
)
def ask(question, mode, top_k, debug):
    """Ask a question to the RAG system."""
    try:
        rag = RAGSystem(config_path=CONFIG_PATH)
        rag.query(question, mode=mode, top_k=top_k, debug=debug)
    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.argument("query")
@click.option(
    "--top-k",
    type=int,
    default=5,
    help="Number of documents to retrieve (default: 5).",
)
def retrieve(query, top_k):
    """Show which documents are retrieved from the vector DB for a given query."""
    try:
        rag = RAGSystem(config_path=CONFIG_PATH)
        results = rag.retrieve(query, top_k=top_k)

        if not results:
            click.echo("No documents retrieved.")
            return

        click.echo(f"\nRetrieved {len(results)} document(s) for query: \"{query}\"\n")
        click.echo("=" * 72)

        for doc in results:
            click.echo(f"[#{doc['rank']}] Metadata: {doc['metadata']}")
            click.echo("-" * 72)
            click.echo(doc["content"])
            click.echo("=" * 72)

    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
def clear():
    """Clear the vector database."""
    if click.confirm("Are you sure you want to clear the entire database?"):
        try:
            rag = RAGSystem(config_path=CONFIG_PATH)
            rag.clear_database()
        except Exception as e:
            click.echo(f"Error: {e}")


@cli.command()
@click.option("--log-path", help="Path to Suricata eve.json (overrides config)")
@click.option("--from-beginning", is_flag=True, help="Process the whole file, not just new lines.")
@click.option("--top-k", type=int, default=5, help="KB documents to retrieve per alert (default: 5).")
def monitor(log_path, from_beginning, top_k):
    """Start monitoring a Suricata eve.json and process alerts with RAG."""
    config = _load_config(CONFIG_PATH)
    suricata_config = config.get("suricata", {})

    target_log = log_path or suricata_config.get("log_path", "/var/log/suricata/eve.json")

    if not os.path.exists(target_log):
        click.echo(f"Error: EVE log not found: {target_log}")
        return

    click.echo(f"Starting Suricata Monitor on {target_log}...")

    monitor = SuricataMonitor(target_log, from_beginning=from_beginning)
    rag = RAGSystem(config_path=CONFIG_PATH)

    try:
        for alert in monitor.follow():
            click.echo(f"\n{alert}")
            query = alert.build_retrieval_query()
            rag.query(query, mode="analyst", top_k=top_k)

    except KeyboardInterrupt:
        click.echo("\nStopping monitor...")
        monitor.stop()


if __name__ == "__main__":
    cli()
