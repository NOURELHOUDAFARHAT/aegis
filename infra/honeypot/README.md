# The honeypot sensor

A **honeypot** is a decoy server. It pretends to be a poorly protected Linux
machine so that attackers on the internet try to break in, and it records
everything they do: the passwords they guess, the commands they type, the
malware they try to download. None of it is real. The attacker is inside
[Cowrie](https://github.com/cowrie/cowrie), an emulator, never inside the VM.

This folder builds one on Oracle Cloud's **Always Free** tier, with Terraform.

```
 internet ──► port 22 / 23 ──► Cowrie container (fake SSH/Telnet) ──► cowrie.json
                                                                          │
 your laptop ──► port 22222 (your IP only) ──► aegis-log-reader ◄─────────┘
       │                                        (read-only, nothing else)
       └──► aegis honeypot collect ──► Kafka ──► Bronze ──► Silver sessions
```

## What protects what

| Risk | Protection |
|---|---|
| Attacker escapes into the VM | Cowrie is an emulator; its container is read-only, has no Linux capabilities, cannot gain privileges, and has memory and process limits |
| The VM attacks someone else | Outbound traffic is limited to web (80/443), time (NTP) and DNS by the cloud firewall; Cowrie's SSH port forwarding is switched off |
| The disk fills with malware | Downloads are capped at 10 MB each |
| Someone reaches the real SSH | It moves to port 22222, open only to your IP, keys only, no passwords, no root |
| AEGIS's key is stolen | That key runs one read-only command. No shell, no forwarding, no writes |
| An accidental bill | Terraform refuses any shape other than the two Always Free ones, and caps CPU, memory and disk at the free allowance |
| You get locked out | The setup script refuses to start Cowrie on port 22 until real SSH is proven to be listening on 22222 |

## Before you start: what this costs and what it asks of you

- **Money: nothing**, if you stay on the Always Free resources. Oracle asks for a
  card during sign-up to verify identity.
- **Your home region is permanent.** Always Free compute exists only there.
  Pick one near you (e.g. `eu-paris-1`, `eu-marseille-1`, `eu-frankfurt-1`).
- **Attack data is personal data.** Attacker IP addresses count as personal
  data under the GDPR. They stay in your private lakehouse, and Phase 9
  pseudonymises them in Silver.

## Setup, step by step

All commands are PowerShell.

### 1. Create the Oracle Cloud account

Sign up at https://signup.cloud.oracle.com and choose your home region.

### 2. Create an API key, so Terraform can act for you

1. In the console: profile icon (top right) → **User settings** → **API keys** → **Add API key**.
2. Choose **Generate API key pair**, then **Download private key**.
3. Move the key somewhere private:
   ```powershell
   New-Item -ItemType Directory -Force $HOME\.oci
   Move-Item $HOME\Downloads\*.pem $HOME\.oci\oci_api_key.pem
   ```
4. Click **Add**. Oracle shows a "Configuration file preview". Copy it into
   `$HOME\.oci\config` and change the `key_file=` line to
   `key_file=~/.oci/oci_api_key.pem`.

### 3. Create two SSH keys

One for you, one for AEGIS. Separate keys mean AEGIS's key can be restricted
without restricting yours.

```powershell
ssh-keygen -t ed25519 -f $HOME\.ssh\aegis_admin  -C "aegis-admin"
ssh-keygen -t ed25519 -f $HOME\.ssh\aegis_reader -C "aegis-reader"
```

### 4. Fill in the variables

```powershell
cd infra\honeypot\terraform
Copy-Item terraform.tfvars.example terraform.tfvars
(Invoke-RestMethod https://ifconfig.me/ip)   # your public IP
```

Edit `terraform.tfvars`:
- `region`: your home region
- `compartment_ocid`: the `tenancy=` value from `$HOME\.oci\config`
- `admin_cidr`: your IP followed by `/32`

`terraform.tfvars` is git-ignored: it holds your home IP.

### 5. Build it

```powershell
terraform init
terraform plan      # read it: it should create 6 resources and change nothing else
terraform apply
```

If apply fails with **"Out of capacity"**, Oracle has no free Arm machines left
in that data centre. Try `availability_domain_index = 1` (or `2`), or set
`shape = "VM.Standard.E2.1.Micro"`, which is smaller but usually available.

### 6. Check the sensor came up

First boot takes about five minutes. Then:

```powershell
$ip = terraform output -raw public_ip
ssh -i $HOME\.ssh\aegis_admin -p 22222 ubuntu@$ip "sudo cat /var/log/aegis-bootstrap.log; sudo docker ps"
```

You should see `real SSH is listening on 22222`, `cowrie started`, and a
running `aegis-cowrie-cowrie-1` container.

> **Never connect to port 22 yourself.** That is the honeypot, and it would
> record you as an attacker.

### 7. Connect AEGIS

Add the output of `terraform output aegis_env` to the `.env` file at the
repository root. Then:

```powershell
aegis honeypot files               # the log files, and how much is collected
aegis honeypot collect --show      # look at real attacks
aegis honeypot collect --to kafka  # into the pipeline
aegis lake sync cowrie             # Kafka -> Bronze
aegis model build                  # Bronze -> silver.honeypot_sessions
```

The first attacks usually arrive within hours: scanners sweep the whole IPv4
internet for open SSH continuously.

## Maintenance

- **Your home IP changed** and SSH times out: update `admin_cidr`, run `terraform apply`.
- **Security updates** install automatically (Ubuntu's unattended-upgrades).
- **Tear it all down**: `terraform destroy`. Collect the logs first; they are
  deleted with the VM.
