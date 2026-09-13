{#
  By default dbt PREFIXES a custom schema with the target schema, so
  `+schema: silver` becomes a schema called `main_silver`. That default exists
  so two developers sharing one warehouse do not overwrite each other.

  This warehouse is a single local file owned by one person, so the prefix buys
  nothing and makes every query uglier. Use the custom schema name as written:
  `silver.kev_vulnerabilities`, not `main_silver.kev_vulnerabilities`.
#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {%- if custom_schema_name is none -%}
        {{ target.schema }}
    {%- else -%}
        {{ custom_schema_name | trim }}
    {%- endif -%}
{%- endmacro %}
