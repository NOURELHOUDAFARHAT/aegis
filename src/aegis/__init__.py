"""AEGIS - a JVM-free threat-intelligence lakehouse.

Layers:
    aegis.sources    collectors for threat feeds and honeypot telemetry
    aegis.streaming  Kafka producers, consumers, schemas and dead-letter handling
    aegis.lakehouse  Iceberg catalogue, table definitions and writers
    aegis.ml         feature engineering, anomaly detection and retrieval
    aegis.api        the FastAPI serving layer
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
