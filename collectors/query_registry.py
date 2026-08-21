import logging

from collectors.bloodhound_queries import QUERIES as _AD_QUERIES
from collectors.azure_queries import AZURE_QUERIES as _AZURE_QUERIES

log = logging.getLogger(__name__)

BUILTIN_QUERIES = {**_AD_QUERIES, **_AZURE_QUERIES}

QUERIES_VERSION = 1


def get_queries():
    """Return the built-in query registry."""
    log.debug("Using built-in queries v%d (%d queries)", QUERIES_VERSION, len(BUILTIN_QUERIES))
    return dict(BUILTIN_QUERIES)
