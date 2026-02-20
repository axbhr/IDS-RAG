# IDS-RAG2

Local RAG implementation using Ollama and ChromaDB, controllable via CLI.

## Prerequisites

1.  **Ollama**: Ensure Ollama is installed and running.
    - Default URL: `http://localhost:11434`
    - Models: You need to pull the models specified in `config.yaml`.
      ```bash
      ollama pull llama3.2
      ollama pull nomic-embed-text
      ```

## Installation

1.  Create a virtual environment (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    OR install in editable mode to use the `ids-rag` command directly:
    ```bash
    pip install -e .
    ```

## Configuration

Edit `config.yaml` to match your Ollama setup.Default uses `llama3.2` for chat and `nomic-embed-text` for embeddings.

## Usage

### 1. Define Data

Create a YAML file (e.g., `data.yaml`) with the content you want to ingest.
Example `data.yaml`:
```yaml
documents:
  - type: text
    content: "My secret project is called X-99."
    metadata:
      category: "secrets"
  
  - type: file
    path: "./docs/manual.txt"
```

### 2. Ingest Data

Run the ingestion command:

```bash
# If installed with pip install -e .
ids-rag ingest data.yaml

# Or using python directly
python src/ids_rag/cli.py ingest data.yaml
```

### 3. Ask Questions

Query the RAG system:

```bash
ids-rag ask "What is project X-99?"
```

### 4. Clear Database

To reset the database:

```bash
ids-rag clear
```
