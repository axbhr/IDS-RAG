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

### 4. Wissensdatenbank (Knowledge Base) - KRITISCHES PROBLEM BEHOBEN
*   **Problem: LLM erkannte Threats nicht aus KB**
    *   Das LLM erhielt Threat-Patterns aus der Knowledge Base, konnte aber nicht richtig abgleichen mit Zeek-Logs
    *   Beispiel: Log mit `orig_bytes=5000000 resp_bytes=500 duration=300s` wurde als "CLEAN" klassifiziert, obwohl es Data Exfiltration ist
    *   Grund: KB war zu deskriptiv ("A single connection with HIGH UPLOAD") statt maschinenlesbar
    *   LLM spekulierte stattdessen über Patterns, die nicht explizit in der KB standen
    *   
*   **Root Cause:**
    1. KB-Struktur war zu Prosa-fokussiert (natürlichsprachige Beschreibungen)
    2. Keine expliziten NOT_MATCH Kriterien (z.B. "conn_state muss S0/REJ sein, NICHT SF")
    3. Schwache Test-Cases in KB → LLM konnte Matching-Logik nicht lernen
    4. Analyst-Prompt war zu allgemein ("compare against patterns" statt mechanischer CHECK)
    
*   **Lösung: Maschinenlesbares KB-Format**
    ```yaml
    CONDITION_1: orig_bytes GREATER_THAN resp_bytes
    CONDITION_2: orig_bytes GREATER_THAN_OR_EQUAL 1000000
    CONDITION_3: duration GREATER_THAN_OR_EQUAL 10
    CONDITION_4: conn_state EQUALS SF
    ALL_CONDITIONS_REQUIRED: YES
    MATCH_EXAMPLE: orig_bytes=5000000 → THREAT
    NO_MATCH_EXAMPLE: orig_bytes=150 → NOT THREAT
    ```
    
*   **Implementierte Fixes:**
    1. KB umstrukturiert: Explizite **CONDITION_N** (statt vager Beschreibungen)
    2. **MATCH_EXAMPLE** und **NO_MATCH_EXAMPLE** hinzugefügt (für LLM-Training)
    3. **ALL_CONDITIONS_REQUIRED: YES** macht Logik binär (nicht interpretierbar)
    4. Analyst-Prompt mechanisiert: "For each threat: Check CONDITION_1...N. If ANY fails → no match"
    5. Modelfile vereinfacht: Keine hardcodierten Rules, nur "Use KB Only"
    6. Analyst-Mode setzt `k=1000` (alle Dokumente), nicht top-10
    
*   **Test-Ergebnisse nach Fix:**
    ✅ Data Exfiltration (5M >> 500 bytes, 300s) → **ERKANNT**
    ✅ SSH Brute Force (port 22, S0) → **ERKANNT**
    ✅ Normal HTTP (150 << 3000 bytes, 0.5s) → **CLEAN** (korrekt)

### 4b. Input-Normalisierung (ENTSCHEIDEND)
*   **Problem:** LLM erhielt KB aber konnte noch nicht richtig matchen (alle Logs → "CLEAN")
*   **Root Cause:** 
    1. Variierende Log-Formate ("duration=120s" vs "duration=0.001s") verwirren LLM beim Parsing
    2. KB-Syntax zu verbos ("GREATER_THAN_OR_EQUAL 1000000") statt mathematisch
    3. Port-Extraction fehlte (dst=10.0.0.5:22 wurde nicht zu dst_port=22 separiert)
    
*   **Lösung - 3 Teile:**
    1. **Normalizer** in `rag_system.py`: Extrahiert alle Key=Value Paare, konvertiert:
       - `duration=120s` → `duration_seconds=120` (numerisch)
       - `src=192.168.1.100:55555` → `src_ip=192.168.1.100 | src_port=55555` (separiert)
       - Alle Bytes zu Integers: `orig_bytes=5000000`
    2. **KB-Syntax** vereinfacht: 
       - `CONDITION_1: orig_bytes > resp_bytes` (statt GREATER_THAN)
       - `CONDITION_2: orig_bytes >= 1000000` (mathematisch)
       - Konkrete MATCH_EXAMPLE/NO_MATCH_EXAMPLE hinzugefügt
    3. **Modelfile** mit echten Beispielen:
       ```
       MATCH_EXAMPLE: dst_port=22 | conn_state=S0 | duration_seconds=0.01 | orig_bytes=0 → THREAT
       ```
       
*   **Ergebnis:**
    ✅ `dst_port=22 | conn_state=S0 | duration_seconds=0.001 | orig_bytes=0` → **"MATCH FOUND: ssh_brute_force"**
    ✅ Token-Ersparnis: Minimal-Prompt in rag_system.py (~50 Tokens), alle Logik in Modelfile (~600 Tokens, persistent)

### 5. LLM Datenqualität Generell
*   **Datenqualität:**
    *   Bloße CVE-Beschreibungen reichen nicht für Netzwerkerkennung.
    *   *Lösung:* Import von **Sigma Rules**. Diese bieten strukturierte Detection-Logik ("Wenn Port 22 und viele Verbindungen -> Brute Force").
*   **Integration:**
    *   Entwicklung eines automatischen Sync-Tools (`ids-rag sync`), das Regeln direkt von GitHub lädt, filtert (nur Netzwerk-relevant) und ingestiert.

### 6. Simulator Realismus
*   Der Simulator (`simulate_zeek_tsv.py`) produzierte anfangs zu einfachen oder zu wenig Traffic, was das Testen des "Batch Processing" erschwerte.
*   Header-Handling im TSV-Stream musste angepasst werden, damit das LLM die Spalten zuordnen kann.
