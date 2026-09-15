"""AEGIS - a JVM-free threat-intelligence lakehouse.

Layers:
    aegis.sources        collectors for threat feeds and honeypot telemetry
    aegis.streaming      Kafka producers, consumers, schemas and dead-letter handling
    aegis.lakehouse      Iceberg catalogue, table definitions and writers
    aegis.modeling       dbt runner for Silver and Gold
    aegis.orchestration  the Dagster asset graph
    aegis.ml             campaign detection, ransomware scoring and semantic search
"""

from aegis._windows_dll import preload_msvc_runtime as _preload_msvc_runtime

# This must run before ANY module imports PyArrow. On Windows, PyArrow loads an
# old bundled C++ runtime that breaks onnxruntime (and therefore `aegis ml
# embed`). Placing the fix in the package's own __init__ means it runs first
# for every entry point - the CLI, Dagster and scripts all import `aegis` before
# anything else in it. See aegis/_windows_dll.py for the measurements.
MSVC_RUNTIME_STATUS = _preload_msvc_runtime()

__version__ = "0.1.0"
__all__ = ["MSVC_RUNTIME_STATUS", "__version__"]
