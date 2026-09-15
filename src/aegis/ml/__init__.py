"""AEGIS machine learning on the threat feeds.

    campaigns   group URLhaus servers into campaigns by what they serve
    ransomware  score exploited CVEs for resemblance to ransomware favourites
    search      semantic search over exploited CVEs with local embeddings

Every module here is pure: it reads Silver from the warehouse, writes its
results to the `ml` schema, and returns a result object. None of them import
MLflow or Dagster. Experiment tracking and scheduling happen where these are
called, so the models stay testable without either.

OWNERSHIP BOUNDARY
dbt owns the staging, silver and gold schemas. Python ML owns `ml`. Writing
model outputs into `gold` would mean two systems managing one schema, and a
dbt rebuild could not tell its own tables from ours.
"""
