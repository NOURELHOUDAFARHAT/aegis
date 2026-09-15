# ---------------------------------------------------------------------------
# One public subnet with a deliberately narrow firewall.
#
# INBOUND - three doors, each for one audience:
#   22    the honeypot's fake SSH        everyone (that is the point)
#   23    the honeypot's fake Telnet     everyone, if enable_telnet
#   22222 the real SSH, for you and AEGIS   admin_cidr only
#
# OUTBOUND - web and time only. A honeypot invites hostile people in; it must
# not become a machine they can use against someone else. Cowrie is an
# emulator, but SSH port forwarding and scripted downloads both make outbound
# connections, so the network enforces the limit instead of trusting the
# software to. Blocked on purpose: SMTP (spam relay), SSH/Telnet (relaying
# brute-force attacks), everything else.
#
# Oracle's Ubuntu images ALSO run a host firewall (iptables) that rejects
# everything except port 22. A port has to be open in both places; the
# cloud-init script handles the host side.
# ---------------------------------------------------------------------------

resource "oci_core_vcn" "honeypot" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.42.0.0/16"]
  display_name   = "aegis-honeypot-vcn"
  dns_label      = "aegishp"
}

resource "oci_core_internet_gateway" "honeypot" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.honeypot.id
  display_name   = "aegis-honeypot-igw"
  enabled        = true
}

resource "oci_core_route_table" "honeypot" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.honeypot.id
  display_name   = "aegis-honeypot-routes"

  route_rules {
    network_entity_id = oci_core_internet_gateway.honeypot.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

resource "oci_core_security_list" "honeypot" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.honeypot.id
  display_name   = "aegis-honeypot-firewall"

  # --- inbound ---------------------------------------------------------------

  ingress_security_rules {
    description = "Honeypot SSH (Cowrie). Open to the internet on purpose."
    protocol    = "6"
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = 22
      max = 22
    }
  }

  dynamic "ingress_security_rules" {
    for_each = var.enable_telnet ? [23] : []

    content {
      description = "Honeypot Telnet (Cowrie). Open to the internet on purpose."
      protocol    = "6"
      source      = "0.0.0.0/0"
      source_type = "CIDR_BLOCK"
      stateless   = false

      tcp_options {
        min = ingress_security_rules.value
        max = ingress_security_rules.value
      }
    }
  }

  ingress_security_rules {
    description = "Real SSH, for administration and log collection. Your network only."
    protocol    = "6"
    source      = var.admin_cidr
    source_type = "CIDR_BLOCK"
    stateless   = false

    tcp_options {
      min = var.admin_ssh_port
      max = var.admin_ssh_port
    }
  }

  ingress_security_rules {
    description = "ICMP 'fragmentation needed', so path MTU discovery works."
    protocol    = "1"
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    stateless   = false

    icmp_options {
      type = 3
      code = 4
    }
  }

  # --- outbound --------------------------------------------------------------

  dynamic "egress_security_rules" {
    for_each = { http = 80, https = 443 }

    content {
      description      = "Outbound ${egress_security_rules.key}: package updates, the container image, attacker download URLs."
      protocol         = "6"
      destination      = "0.0.0.0/0"
      destination_type = "CIDR_BLOCK"
      stateless        = false

      tcp_options {
        min = egress_security_rules.value
        max = egress_security_rules.value
      }
    }
  }

  egress_security_rules {
    description      = "NTP. Accurate clocks matter: every event timestamp comes from this machine."
    protocol         = "17"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    stateless        = false

    udp_options {
      min = 123
      max = 123
    }
  }

  dynamic "egress_security_rules" {
    for_each = { "6" = "TCP", "17" = "UDP" }

    content {
      description      = "DNS (${egress_security_rules.value}) to the VCN resolver only."
      protocol         = egress_security_rules.key
      destination      = "169.254.169.254/32"
      destination_type = "CIDR_BLOCK"
      stateless        = false
    }
  }
}

resource "oci_core_subnet" "honeypot" {
  compartment_id             = var.compartment_ocid
  vcn_id                     = oci_core_vcn.honeypot.id
  cidr_block                 = "10.42.1.0/24"
  display_name               = "aegis-honeypot-public"
  dns_label                  = "public"
  route_table_id             = oci_core_route_table.honeypot.id
  security_list_ids          = [oci_core_security_list.honeypot.id]
  prohibit_public_ip_on_vnic = false
}
