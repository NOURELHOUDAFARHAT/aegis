data "oci_identity_availability_domains" "all" {
  compartment_id = var.compartment_ocid
}

# The newest Ubuntu 24.04 image built for the chosen shape. Filtering by shape
# picks the right CPU architecture automatically: Arm for A1, x86 for E2.
data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = var.shape
  state                    = "AVAILABLE"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

locals {
  is_flex_shape = endswith(var.shape, ".Flex")
}

resource "oci_core_instance" "honeypot" {
  availability_domain = data.oci_identity_availability_domains.all.availability_domains[var.availability_domain_index].name
  compartment_id      = var.compartment_ocid
  display_name        = "aegis-honeypot"
  shape               = var.shape

  dynamic "shape_config" {
    for_each = local.is_flex_shape ? [1] : []

    content {
      ocpus         = var.ocpus
      memory_in_gbs = var.memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = var.boot_volume_gb
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.honeypot.id
    assign_public_ip = true
    hostname_label   = "sensor"
  }

  metadata = {
    # pathexpand: Terraform's file() does not understand "~" on its own.
    ssh_authorized_keys = trimspace(file(pathexpand(var.admin_ssh_public_key_path)))
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      admin_ssh_port    = var.admin_ssh_port
      reader_public_key = trimspace(file(pathexpand(var.reader_ssh_public_key_path)))
      reader_script     = file("${path.module}/../aegis-log-reader.sh")
      compose_file      = templatefile("${path.module}/../compose.yaml.tftpl", { enable_telnet = var.enable_telnet })
      bootstrap_script  = templatefile("${path.module}/../bootstrap.sh.tftpl", { admin_ssh_port = var.admin_ssh_port })
    }))
  }

  lifecycle {
    # Oracle publishes new Ubuntu images regularly. Without this, the next
    # `terraform apply` after a release would destroy and recreate the sensor,
    # losing every log not yet collected.
    ignore_changes = [source_details[0].source_id, metadata["user_data"]]
  }
}
