import os
import yaml
import re
from typing import List, Dict, Any

from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader, TextLoader


class RAGSystem:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)

        # Initialize Embedding Model
        self.embeddings = OllamaEmbeddings(
            base_url=self.config["ollama"]["base_url"],
            model=self.config["ollama"]["embedding_model"],
        )

        # Initialize Vector Store (Chroma)
        persist_directory = self.config["database"]["persist_directory"]
        collection_name = self.config["database"]["collection_name"]

        self.vector_store = Chroma(
            collection_name=collection_name,
            embedding_function=self.embeddings,
            persist_directory=persist_directory,
        )

        # Initialize LLM
        self.llm = ChatOllama(
            base_url=self.config["ollama"]["base_url"],
            model=self.config["ollama"]["model"],
        )

    def _load_config(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def ingest_from_yaml(self, data_yaml_path: str):
        """Loads data from a YAML file and adds it to the vector store."""
        print(f"Loading data from {data_yaml_path}...")
        with open(data_yaml_path, "r") as f:
            data = yaml.safe_load(f)

        documents = []

        # Check if 'documents' or 'data' key exists, otherwise assume list
        items = data.get("documents", data) if isinstance(data, dict) else data

        if not isinstance(items, list):
            print("Error: YAML content must be a list or contain a 'documents' list.")
            return

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000, chunk_overlap=200
        )

        for item in items:
            doc_type = item.get("type", "text")
            metadata = item.get("metadata", {})

            if doc_type == "text":
                content = item.get("content", "")
                if content:
                    metas = metadata.copy()
                    metas["source"] = "yaml_text"
                    documents.append(Document(page_content=content, metadata=metas))

            elif doc_type == "file":
                path = item.get("path")
                # Resolve relative path
                if path and not os.path.isabs(path):
                    path = os.path.join(os.path.dirname(data_yaml_path), path)

                if path and os.path.exists(path):
                    metas = metadata.copy()
                    metas["source"] = path

                    if path.lower().endswith(".pdf"):
                        loader = PyPDFLoader(path)
                        pages = loader.load()
                        for page in pages:
                            page.metadata.update(metas)
                            page.metadata["page"] = (
                                page.metadata.get("page", 0) + 1
                            )  # PyPDF page numbers
                            documents.append(page)
                    else:
                        # Assume text
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read()
                            documents.append(
                                Document(page_content=content, metadata=metas)
                            )
                else:
                    print(f"Warning: File not found: {path} (from {data_yaml_path})")

        if documents:
            # Split documents
            splits = text_splitter.split_documents(documents)
            print(f"Adding {len(splits)} document chunks to vector store...")
            self.vector_store.add_documents(documents=splits)
            print("Ingestion complete.")
        else:
            print("No valid documents found to ingest.")

    def _normalize_zeek_log(self, log_input: str) -> str:
        """
        Normalizes Zeek log input to a consistent machine-readable format.
        Converts: "src=192.168.1.100:55555 dst=10.0.0.5:22 duration=120s orig_bytes=2500000 resp_bytes=250 conn_state=SF"
        To:       "NORMALIZED LOG: src_ip=192.168.1.100 | src_port=55555 | dst_ip=10.0.0.5 | dst_port=22 | duration_seconds=120 | ..."
        """
        # Extract key=value pairs
        pattern = r'(\w+)=([\w\.\:]+)'
        matches = re.findall(pattern, log_input)
        
        if not matches:
            return log_input  # Return as-is if no matches
        
        normalized = {}
        
        for key, value in matches:
            lower_key = key.lower()
            
            # Handle src/dst with IP:Port format
            if lower_key == "src":
                parts = value.split(":")
                if len(parts) == 2:
                    normalized["src_ip"] = parts[0]
                    try:
                        normalized["src_port"] = int(parts[1])
                    except:
                        normalized["src_port"] = parts[1]
                else:
                    normalized["src"] = value
            
            elif lower_key == "dst":
                parts = value.split(":")
                if len(parts) == 2:
                    normalized["dst_ip"] = parts[0]
                    try:
                        normalized["dst_port"] = int(parts[1])
                    except:
                        normalized["dst_port"] = parts[1]
                else:
                    normalized["dst"] = value
            
            # Handle duration: convert "120s" to "120"
            elif lower_key == "duration":
                # Remove 's', 'ms', etc.
                value = re.sub(r'[a-zA-Z]+$', '', value)
                try:
                    normalized["duration_seconds"] = float(value)
                except:
                    normalized["duration_seconds"] = value
            
            # Handle numeric fields
            elif lower_key in ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]:
                try:
                    normalized[lower_key] = int(value)
                except:
                    normalized[lower_key] = value
            
            # Handle string fields
            else:
                normalized[lower_key] = value
        
        # Build formatted output
        output = "NORMALIZED LOG: "
        fields = []
        for k, v in normalized.items():
            fields.append(f"{k}={v}")
        output += " | ".join(fields)
        
        return output

    def query(self, question: str, mode: str = "chat", top_k: int = 3, debug: bool = False):
        """Queries the RAG system. Mode can be 'chat' or 'analyst'. top_k=0 retrieves all."""
        # Normalize question if analyst mode (for Zeek logs)
        if mode == "analyst" and "Zeek Log:" in question:
            log_part = question.split("Zeek Log:")[1].strip()
            normalized = self._normalize_zeek_log(log_part)
            question = f"Zeek Log: {normalized}"
            
            if debug:
                print("\n[DEBUG] NORMALIZED LOG INPUT:")
                print(f"  {normalized}")
                print()
        
        # Determine k: if top_k is 0, get all documents, otherwise use the specified value
        if top_k == 0:
            # Get approximate count of documents or just use a very large number
            k = 1000  # Effectively "all" for most cases
        else:
            k = top_k
        
        # For analyst mode, ALWAYS get all documents to ensure complete pattern matching
        if mode == "analyst":
            k = 1000

        # Retrieve documents
        retriever = self.vector_store.as_retriever(search_kwargs={"k": k})

        if mode == "analyst":
            # Minimal template - all logic is in Modelfile system prompt
            template = """Knowledge Base:
{context}

Analyze log:
{question}"""
        else:
            # Chat mode: We need a STRONG override to break the Modelfile system prompt
            template = """
                        SYSTEM OVERRIDE: You are a helpful assistant explaining the contents of the knowledge base.
                        IGNORE the 'Network IDS Analyst' persona. DO NOT look for logs. DO NOT output 'CLEAN'.
                        Just answer the user's question based on the context provided.

                        Context:
                        {context}

                        Question: {question}
                        """

        prompt = ChatPromptTemplate.from_template(template)

        def format_docs(docs):
            return "\n\n".join([d.page_content for d in docs])

        chain = (
            {"context": retriever | format_docs, "question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
        )

        print("\nThinking...")
        for chunk in chain.stream(question):
            print(chunk, end="", flush=True)
        print("\n")

    def clear_database(self):
        """Clears the vector store."""
        self.vector_store.delete_collection()
        print("Database cleared.")
