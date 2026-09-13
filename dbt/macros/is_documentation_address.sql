{#
  True when an IPv4 address falls in a range RFC 5737 reserves for
  documentation and examples:

      192.0.2.0/24      TEST-NET-1
      198.51.100.0/24   TEST-NET-2
      203.0.113.0/24    TEST-NET-3

  These addresses are never routed on the public internet, so no real attacker,
  C2 server or Tor exit can ever use one. Any that reach the lakehouse were put
  there by tests, demos or example code.

  WHY THIS MACRO EXISTS
  The first dbt run found 9 such rows in bronze.feodo: 203.0.113.10 ("DemoBot",
  from scripts/demo_contracts.py) and 198.51.100.7 (from an integration test),
  both of which had published through the real pipeline. Filtering by these
  reserved ranges is a principled rule - not a hardcoded list of the two
  addresses that happened to leak - so it also catches whatever the next test
  writes.

  Bronze keeps the rows: it records what arrived, and they did arrive. Silver is
  where they are excluded, and a singular test asserts none leak past it.
#}
{% macro is_documentation_address(column) -%}
    (
        {{ column }} like '192.0.2.%'
        or {{ column }} like '198.51.100.%'
        or {{ column }} like '203.0.113.%'
    )
{%- endmacro %}
