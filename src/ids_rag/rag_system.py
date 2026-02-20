import os
import yaml
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

    def query(self, question: str, mode: str = "chat"):
        """Queries the RAG system. Mode can be 'chat' or 'analyst'."""
        # Retrieve more documents (k=10) to cover "Data Exfiltration" if it's buried
        retriever = self.vector_store.as_retriever(search_kwargs={"k": 10})

        if mode == "analyst":
            # The strict analyst prompt is handled by the ModelFile system prompt itself
            # We just pass the data through broadly
            template = """
Context (Attack Patterns):
{context}

Data to Analyze:
{question}
"""
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
