# IDS-RAG: Threat Intelligence System with Local LLM and Vector Search

A proof-of-concept Intrusion Detection System (IDS) that combines Retrieval-Augmented Generation (RAG) with local LLM inference for threat detection and network security analysis.

## Overview

**IDS-RAG** integrates:
- **Vector Database** (ChromaDB): Semantic search over threat intelligence patterns
- **Local LLM** (Ollama/llama3.2): Context-aware threat analysis without external API calls
- **Zeek Log Processing**: Normalized parsing of network flow data
- **YAML-based Knowledge Base**: Machine-readable threat definitions with condition matching

The system analyzes network logs (Zeek TSV format) by retrieving relevant threat patterns from the Knowledge Base and using LLM reasoning to classify activities as threats or benign traffic.

## Prerequisites

- **Python 3.10+**
- **Ollama** (running locally)
  - URL: `http://localhost:11434` (configurable)
  - Required models:
    ```bash
    ollama pull llama3.2          # LLM for threat analysis
    ollama pull nomic-embed-text  # Embeddings for semantic search
    ```

## Installation

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd IDS-RAG
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install package:
   ```bash
   pip install -e .
   ```

## Configuration

Edit `config.yaml` to customize:
- Ollama endpoint URL
- Model names (LLM and embedding model)
- ChromaDB persistence path
- Collection names

Example:
```yaml
ollama:
  base_url: "http://localhost:11434"
  llm_model: "llama3.2"
  embed_model: "nomic-embed-text"

chroma:
  persist_directory: "./chroma_db"
```

## Knowledge Base Format

Threats are defined in `knowledge_base/threat_intel.yaml` with machine-readable conditions:

```yaml
threats:
  - name: "SSH_BRUTE_FORCE"
    severity: "HIGH"
    conditions:
      - "CONDITION_1: dst_port = 22"
      - "CONDITION_2: conn_state = S0 OR conn_state = REJ"
      - "CONDITION_3: duration_seconds < 1"
      - "CONDITION_4: orig_bytes = 0 OR orig_bytes < 100"
    all_conditions_required: true
    match_example: "dst_port=22 | conn_state=S0 | duration_seconds=0.01 | orig_bytes=0"
```

## Usage

### 1. Ingest Threat Intelligence

Load threat patterns into the vector database:
```bash
ids-rag ingest knowledge_base/threat_intel.yaml
```

### 2. Query with a Network Log

Analyze a Zeek log entry:
```bash
ids-rag ask "ts=1234567890 uid=abc src=192.168.1.100:55555 dst=10.0.0.5:22 \
  duration=0.001s orig_bytes=0 resp_bytes=0 conn_state=S0 service=-"
```

With debug output to see normalization:
```bash
ids-rag ask --debug "ts=1234567890 uid=abc src=192.168.1.100:55555 dst=10.0.0.5:22 ..."
```

Control retrieval count:
```bash
ids-rag ask --top-k 5 "Your log here"
```

### 3. Monitor Live Zeek Stream

Process continuous Zeek logs:
```bash
ids-rag monitor /var/log/zeek/conn.log
```

### 4. Clear Vector Database

Reset the threat intelligence store:
```bash
ids-rag clear
```

## System Components

### `src/ids_rag/rag_system.py`
Core RAG pipeline:
- **RAGSystem**: Manages ChromaDB collection, retrieval, and LLM queries
- **_normalize_zeek_log()**: Converts raw log strings into standard format
  - Parses `duration=120s` → `duration_seconds=120.0`
  - Splits `src=192.168.1.100:55555` → `src_ip | src_port`
  - Returns: `NORMALIZED LOG: field1=value | field2=value | ...`

### `src/ids_rag/cli.py`
Command-line interface with commands:
- `ask`: Query threat analysis
- `ingest`: Load YAML knowledge base
- `clear`: Reset database
- `sync`: Synchronize threat intelligence files
- `monitor`: Stream live log analysis

### `Modelfile`
Ollama system prompt defining threat-matching behavior:
- Explicit condition evaluation rules
- Example-based learning
- Output constraints (one-line responses)

## Limitations & Notes

- **LLM Hallucination**: llama3.2 may occasionally misclassify logs, especially on complex multi-condition patterns
- **Token Context**: Limited context window (~8K tokens) restricts session analysis scope
- **Latency**: LLM inference (~100-500ms per query) unsuitable for real-time network monitoring
- **Single-Event Analysis**: Current design analyzes individual logs; temporal/sequence analysis not yet implemented

## Project Structure

```
.
├── Modelfile                      # Ollama system prompt
├── config.yaml                    # Configuration
├── knowledge_base/
│   └── threat_intel.yaml         # Threat definitions
├── chroma_db/                    # Persisted vector database
└── src/ids_rag/
    ├── rag_system.py            # Core RAG implementation
    ├── cli.py                   # CLI interface
    ├── knowledge_sync.py        # Knowledge base sync utilities
    └── zeek_monitor.py          # Live log monitoring
```

## Future Work

- Session-based sequence analysis (attack chains)
- Temporal pattern detection across multiple events
- Performance benchmarking vs. rule-based systems (Suricata)
- Advanced anomaly detection with statistical baselines

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

More information: [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)
