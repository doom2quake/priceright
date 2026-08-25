"""Keyless, deterministic test environment: in-memory state, offline rails."""

import os

os.environ.setdefault("PRICERIGHT_IN_MEMORY_STATE", "1")
os.environ.setdefault("PRICERIGHT_OFFLINE", "1")
