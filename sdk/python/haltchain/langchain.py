"""Compatibility shim: `from haltchain.langchain import HaltChainCallbackHandler`."""
from .langchain_handler import HaltChainCallbackHandler

__all__ = ["HaltChainCallbackHandler"]
