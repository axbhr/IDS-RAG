from setuptools import setup, find_namespace_packages

setup(
    name="ids-rag",
    version="0.1.0",
    packages=find_namespace_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click",
        "langchain",
        "langchain-community",
        "langchain-ollama",
        "langchain-chroma",
        "chromadb",
        "fastembed",
        "pyyaml",
    ],
    entry_points="""
        [console_scripts]
        ids-rag=ids_rag.cli:cli
    """,
)
