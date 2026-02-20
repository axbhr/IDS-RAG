# Entwicklungsprotokoll: IDS-RAG System

## Herausforderungen & Probleme

### 1. Technische Kompatibilität
*   **Python Version:** Initialer Versuch mit Python 3.14 schlug fehl, da `ChromaDB` (via `pydantic` v1 Core) und `langchain-chroma` noch nicht kompatibel waren.
    *   *Lösung:* Downgrade auf Python 3.12 mittels `uv venv --python 3.12`.

### 2. Datenformat & Token-Effizienz
*   **JSON vs. TSV:**
    *   Zeek-Logs im JSON-Format verbrauchten zu viele Tokens im LLM-Kontextfenster durch wiederholte Key-Namen (`id.orig_h`, `id.resp_p`).
    *   *Lösung:* Umstellung auf TSV (Tab-Separated Values) mit einmaligem Header. Das LLM muss nun aber Kontext zu Spaltenpositionen erhalten.

### 3. LLM Halluzinationen (False Positives)
*   **Kontext-Verwirrung:**
    *   Das LLM erhielt RAG-Kontext (Sigma Rules) und dachte fälschlicherweise, diese Regeln seien *in* den Logs gefunden worden, obwohl sie nur als Referenz dienten.
    *   Erfand Prozessnamen (`Cmstp.exe`) oder User-Agents, die in Network-Flow-Logs (`conn.log`) technisch gar nicht existieren können.
*   **Fehlende "Grounding":**
    *   Das Modell alarmierte basierend auf vagen Beschreibungen ohne konkreten Beweis in den Logdaten.
    *   *Lösung:* Prompt-Engineering verschärft ("STRICT RULES", "MUST CITE LOG LINE").
    *   *Lösung 2 (Work in Progress):* Eigenes Ollama `Modelfile` (`ids-analyst`), um System-Instruktionen fest zu verankern ("You are a strictly logical NIDS Analyst").

### 4. Wissensdatenbank (Knowledge Base)
*   **Datenqualität:**
    *   Bloße CVE-Beschreibungen reichen nicht für Netzwerkerkennung.
    *   *Lösung:* Import von **Sigma Rules**. Diese bieten strukturierte Detection-Logik ("Wenn Port 22 und viele Verbindungen -> Brute Force").
*   **Integration:**
    *   Entwicklung eines automatischen Sync-Tools (`ids-rag sync`), das Regeln direkt von GitHub lädt, filtert (nur Netzwerk-relevant) und ingestiert.

### 5. Simulator Realismus
*   Der Simulator (`simulate_zeek_tsv.py`) produzierte anfangs zu einfachen oder zu wenig Traffic, was das Testen des "Batch Processing" erschwerte.
*   Header-Handling im TSV-Stream musste angepasst werden, damit das LLM die Spalten zuordnen kann.
