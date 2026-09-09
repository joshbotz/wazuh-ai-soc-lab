terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.3"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --------------------------------------------------------------------------
# Data Sources
# --------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --------------------------------------------------------------------------
# VPC & Networking
# --------------------------------------------------------------------------

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "wazuh-ai-soc-lab"
    Project     = "ai-csl-wazuh-lab"
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name    = "ai-csl-wazuh-lab-igw"
    Project = "ai-csl-wazuh-lab"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false  # manager gets Elastic IP; agent is internal only

  tags = {
    Name    = "ai-csl-wazuh-lab-public"
    Project = "ai-csl-wazuh-lab"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name    = "ai-csl-wazuh-lab-public-rt"
    Project = "ai-csl-wazuh-lab"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --------------------------------------------------------------------------
# Security Groups
# --------------------------------------------------------------------------

resource "aws_security_group" "wazuh_manager" {
  name        = "wazuh-manager-sg"
  description = "Security group for Wazuh manager"
  vpc_id      = aws_vpc.lab.id

  # SSH from your IP
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # Wazuh Dashboard (HTTPS)
  ingress {
    description = "Wazuh Dashboard"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # Wazuh agent communication
  ingress {
    description = "Wazuh agent communication"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Wazuh agent enrollment
  ingress {
    description = "Wazuh agent enrollment"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Wazuh API
  ingress {
    description = "Wazuh API"
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # Wazuh Indexer (for MCP server alert queries)
  ingress {
    description = "Wazuh Indexer API"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # Wazuh MCP server (HTTP, bearer-auth). Pre-installed on the manager by
  # user_data. Same security model as the dashboard: IP-restricted, bearer
  # token on top. The L3 security teaching covers the threat model of
  # exposing this — students learn to put it behind a VPN or bastion in prod.
  ingress {
    description = "Wazuh MCP server (HTTP + bearer)"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "wazuh-manager-sg"
    Project = "ai-csl-wazuh-lab"
  }
}

resource "aws_security_group" "wazuh_agent" {
  name        = "wazuh-agent-sg"
  description = "Security group for CloudVault agent instances"
  vpc_id      = aws_vpc.lab.id

  # SSH from your IP
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # CloudVault Customer Portal (nginx on web-server-01)
  ingress {
    description = "CloudVault portal HTTP (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }
  ingress {
    description = "CloudVault portal HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # CloudVault API (Python HTTPS daemon on app-server-01)
  ingress {
    description = "CloudVault API HTTPS"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # Inter-agent traffic (for attack simulations — port scans, lateral movement,
  # and SSH brute force from dev-server-01 → web-server-01 in scenario 1).
  # Wide TCP range is intentional for lab; production would restrict to specific
  # service ports only.
  ingress {
    description = "Inter-agent lab traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "wazuh-agent-sg"
    Project = "ai-csl-wazuh-lab"
  }
}

# --------------------------------------------------------------------------
# Elastic IP for Wazuh Manager
# --------------------------------------------------------------------------

resource "aws_eip" "wazuh_manager" {
  domain = "vpc"

  tags = {
    Name    = "wazuh-manager-eip"
    Project = "ai-csl-wazuh-lab"
  }
}

resource "aws_eip_association" "wazuh_manager" {
  instance_id   = aws_instance.wazuh_manager.id
  allocation_id = aws_eip.wazuh_manager.id
}

# --------------------------------------------------------------------------
# EC2 Instances
# --------------------------------------------------------------------------

resource "aws_instance" "wazuh_manager" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.manager_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.wazuh_manager.id]
  private_ip             = "10.0.1.10"  # static IP so agents can reach by hostname

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  # Wrap our shell script in a proper cloud-init MIME archive with gzip+base64
  # so we stay under AWS's 16KB user_data limit. Plain `base64gzip()` doesn't
  # work — cloud-init needs the MIME wrapper to recognize the content type.
  user_data_base64 = data.cloudinit_config.manager.rendered

  tags = {
    Name        = "wazuh-manager"
    Project     = "ai-csl-wazuh-lab"
    Role        = "manager"
    Environment = var.environment
  }
}

# --------------------------------------------------------------------------
# CloudVault Financial Agent Instances
# --------------------------------------------------------------------------

locals {
  # Static private IPs so agents can resolve each other by hostname via /etc/hosts.
  # AWS reserves .0-.3 and .255 in each subnet; we start at .10 with 10-IP spacing
  # to leave room for future growth.
  cloudvault_agents = {
    "web-server-01" = {
      role       = "CloudVault Web Server"
      private_ip = "10.0.1.20"
    }
    "app-server-01" = {
      role       = "CloudVault App Server"
      private_ip = "10.0.1.30"
    }
    "dev-server-01" = {
      role       = "CloudVault Dev Server"
      private_ip = "10.0.1.40"
    }
  }
}

resource "aws_instance" "cloudvault_agent" {
  for_each = local.cloudvault_agents

  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.agent_instance_type
  key_name                    = var.key_name
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.wazuh_agent.id]
  associate_public_ip_address = true
  private_ip                  = each.value.private_ip

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  # Cloud-init MIME archive with gzip+base64 — see cloudinit_config data
  # source below. Required because the agent script with inline workload
  # setup exceeds AWS's 16KB raw user_data limit (~20KB uncompressed).
  user_data_base64 = data.cloudinit_config.agent[each.key].rendered

  depends_on = [aws_instance.wazuh_manager]

  tags = {
    Name        = each.key
    Project     = "ai-csl-wazuh-lab"
    Role        = each.value.role
    Environment = var.environment
  }
}

# --------------------------------------------------------------------------
# Cloud-init user_data (MIME + gzip + base64)
# --------------------------------------------------------------------------
# AWS EC2 enforces a 16KB raw limit on user_data. Our agent script is ~20KB
# with the inline CloudVault workloads. The `cloudinit_config` data source
# builds a MIME multipart archive that cloud-init recognizes, then gzips and
# base64-encodes it. Net wire format ≈ 4-5KB. Much headroom.

data "cloudinit_config" "manager" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    filename     = "wazuh_manager.sh"
    content = templatefile("${path.module}/user_data/wazuh_manager.sh", {
      wazuh_installer_series = var.wazuh_installer_series
    })
  }
}

data "cloudinit_config" "agent" {
  for_each = local.cloudvault_agents

  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    filename     = "wazuh_agent.sh"
    content = templatefile("${path.module}/user_data/wazuh_agent.sh", {
      manager_ip    = aws_instance.wazuh_manager.private_ip
      agent_name    = each.key
      wazuh_version = var.wazuh_version
      # Static IPs for all agents — used to populate /etc/hosts so agents
      # can resolve each other by hostname. Fixes v4's TARGET_IP hardcoding bug
      # where the generator script couldn't reach web-server-01 when its IP
      # didn't happen to match the hardcoded 10.0.1.12.
      web_server_ip = local.cloudvault_agents["web-server-01"].private_ip
      app_server_ip = local.cloudvault_agents["app-server-01"].private_ip
      dev_server_ip = local.cloudvault_agents["dev-server-01"].private_ip
      # Stage the events generator as base64 so the cloud-init script can decode
      # it atomically. Avoids the inline-heredoc fragility that caused v3's
      # deployed script to diverge from the repo source.
      events_generator_b64 = base64encode(file("${path.module}/../scripts/agent-events-generator.sh"))
    })
  }
}
