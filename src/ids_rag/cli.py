import click
import os
import time
import json
from .rag_system import RAGSystem
from .zeek_monitor import ZeekMonitor
from .knowledge_sync import sync_sigma_rules

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
    """Download and process Sigma rules from the internet."""
    output_file = "knowledge_base/sigma_rules.yaml"
    if sync_sigma_rules(output_file):
        if do_ingest:
            click.echo("\nAuto-ingesting new rules...")
            try:
                rag = RAGSystem(config_path=CONFIG_PATH)
                rag.ingest_from_yaml(output_file)
            except Exception as e:
                click.echo(f"Error during ingestion: {e}")
        else:
            click.echo(
                "\nSync complete. Run 'ids-rag ingest' to load the new rules into the database."
            )
    else:
        click.echo("Sync failed.")


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
@click.option("--mode", type=click.Choice(["chat", "analyst"]), default="chat", help="Switch between 'chat' (explanatory) and 'analyst' (strict detection) mode.")
def ask(question, mode):
    """Ask a question to the RAG system."""
    try:
        rag = RAGSystem(config_path=CONFIG_PATH)
        rag.query(question, mode=mode)
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
@click.option("--log-path", help="Path to Zeek log file (overrides config)")
@click.option("--interval", type=int, help="Interval in seconds (overrides config)")
def monitor(log_path, interval):
    """Start monitoring Zeek logs and process with RAG."""
    config = _load_config(CONFIG_PATH)
    zeek_config = config.get("zeek", {})

    # Defaults
    target_log = log_path or zeek_config.get("log_path", "./logs/conn.json")
    poll_interval = interval or zeek_config.get("interval", 10)

    if not os.path.exists(target_log):
        click.echo(f"Error: Log file not found: {target_log}")
        click.echo("Make sure Zeek is running or create a dummy file for testing.")
        return

    click.echo(f"Starting Zeek Monitor on {target_log} (Interval: {poll_interval}s)...")

    zeek_mon = ZeekMonitor(target_log, poll_interval)
    rag = RAGSystem(config_path=CONFIG_PATH)

    try:
        for batch in zeek_mon.follow():
            if not batch:
                continue

            click.echo(f"\n[Zeek Monitor] Processing batch of {len(batch)} records...")

            # Format batch for LLM. If JSON, dump. If strings, join.
            if isinstance(batch[0], dict):
                batch_text = json.dumps(batch, indent=2)
            else:
                batch_text = "\n".join(batch)

            # Identify columns for context
            zeek_columns = "ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes, tunnel_parents"

            query = f"""
            ANALYZE BATCH:
            Columns: {zeek_columns}
            
            Logs (TSV):
            {batch_text}
            """

            rag.query(query, mode="analyst")

    except KeyboardInterrupt:
        click.echo("\nStopping monitor...")
        zeek_mon.stop()


if __name__ == "__main__":
    cli()
