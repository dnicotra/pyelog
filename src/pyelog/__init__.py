from .pyelog import (
    ElogClient,
    ElogError
)
from .pyelog import (
    ElogConnectionError,
    ElogAuthenticationError,
    ElogSubmissionError,
    ElogRetrievalError,
    submit_entry,
    retrieve_entry
)

"""PyElog - Python ELOG Client Library
This library provides a Python interface to interact with ELOG (Electronic Logbook) servers.
"""

__version__ = "0.1.0"
__author__ = "Davide Nicotra"
__license__ = "GPL-3.0+"

__all__ = [
    "ElogClient",
    "ElogError",
    "ElogConnectionError",
    "ElogAuthenticationError",
    "ElogSubmissionError",
    "ElogRetrievalError",
    "submit_entry",
    "retrieve_entry"
]