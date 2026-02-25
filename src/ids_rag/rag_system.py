# IDS-RAG: Intrusion Detection System with Retrieval-Augmented Generation
# Copyright (C) 2026 - This file is part of IDS-RAG.
# Licensed under GNU General Public License v3.0
# See LICENSE file for details or visit https://www.gnu.org/licenses/gpl-3.0.html

import os
import yaml
from typing import List, Dict, Any

from fastembed import TextEmbedding
from langchain_core.embeddings import Embeddings
from langchain_ollama import ChatOllama
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader, TextLoader


class BGEEmbeddings(Embeddings):
    """LangChain-compatible wrapper around fastembed.TextEmbedding (ONNX, no torch)."""

    def __init__(self, model_name: str = "BAAI/bge-m3"):
        self._model = TextEmbedding(model_name=model_name)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [list(v) for v in self._model.embed(texts)]

    def embed_query(self, text: str) -> List[float]:
        return list(next(self._model.embed([text])))


class RAGSystem:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)

        # Initialize Embedding Model via fastembed (ONNX, no torch)
        self.embeddings = BGEEmbeddings(model_name="intfloat/multilingual-e5-large")

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

    def query(
        self, question: str, mode: str = "chat", top_k: int = 5, debug: bool = False
    ):
        """Queries the RAG system. Mode can be 'chat' or 'analyst'. top_k=0 retrieves all."""
        k = 1000 if top_k == 0 else top_k

        if debug:
            print(f"\n[DEBUG] QUERY: {question[:200]}")
            print(f"[DEBUG] mode={mode} top_k={k}\n")

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

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Returns the documents retrieved from the vector store for a given query without calling the LLM."""
        retriever = self.vector_store.as_retriever(search_kwargs={"k": top_k})
        docs = retriever.invoke(query)
        results = []
        for i, doc in enumerate(docs, 1):
            results.append({
                "rank": i,
                "content": doc.page_content,
                "metadata": doc.metadata,
            })
        return results

    def clear_database(self):
        """Clears the vector store."""
        self.vector_store.delete_collection()
        print("Database cleared.")
