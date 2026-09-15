output "public_ip" {
  description = "The honeypot's address. Attackers will find it on their own, usually within hours."
  value       = oci_core_instance.honeypot.public_ip
}

output "admin_ssh" {
  description = "How you log in to administer the VM."
  value       = "ssh -p ${var.admin_ssh_port} ubuntu@${oci_core_instance.honeypot.public_ip}"
}

output "aegis_env" {
  description = "Lines to add to your .env so AEGIS can collect the logs."
  value       = <<-EOT
    AEGIS_HONEYPOT_HOST=${oci_core_instance.honeypot.public_ip}
    AEGIS_HONEYPOT_PORT=${var.admin_ssh_port}
    AEGIS_HONEYPOT_USER=aegis
  EOT
}

output "image" {
  description = "The Ubuntu image the sensor was built from."
  value       = data.oci_core_images.ubuntu.images[0].display_name
}
