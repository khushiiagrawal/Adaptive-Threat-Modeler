# VULNERABILITY: Shadow Infrastructure
# This Terraform file provisions infrastructure outside of standard pipelines
# INTENTIONALLY INSECURE FOR DEMO - Do not use in production!

terraform {
  required_version = ">= 0.12"
  
  # VULNERABLE: No backend configuration
  # VULNERABLE: No state management
  # VULNERABLE: No remote state storage
  # VULNERABLE: No state locking
}

# VULNERABLE: No provider configuration
# VULNERABLE: No region specification
# VULNERABLE: No credentials management

# VULNERABLE: Shadow VPC - not tracked in main infrastructure
resource "aws_vpc" "shadow_vpc" {
  cidr_block = "10.0.0.0/16"
  
  # VULNERABLE: No tags for tracking
  # VULNERABLE: No cost allocation tags
  # VULNERABLE: No security tags
  
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# VULNERABLE: Shadow subnet with public access
resource "aws_subnet" "shadow_public_subnet" {
  vpc_id            = aws_vpc.shadow_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  
  # VULNERABLE: Public subnet with auto-assign public IPs
  map_public_ip_on_launch = true
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Internet gateway for public access
resource "aws_internet_gateway" "shadow_igw" {
  vpc_id = aws_vpc.shadow_vpc.id
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Route table with public internet access
resource "aws_route_table" "shadow_public_rt" {
  vpc_id = aws_vpc.shadow_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.shadow_igw.id
  }
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Route table association
resource "aws_route_table_association" "shadow_public_rta" {
  subnet_id      = aws_subnet.shadow_public_subnet.id
  route_table_id = aws_route_table.shadow_public_rt.id
}

# VULNERABLE: Overly permissive security group
resource "aws_security_group" "shadow_sg" {
  name        = "shadow-security-group"
  description = "Shadow infrastructure security group"
  vpc_id      = aws_vpc.shadow_vpc.id

  # VULNERABLE: SSH access from anywhere
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Allows access from anywhere
  }

  # VULNERABLE: HTTP access from anywhere
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Allows access from anywhere
  }

  # VULNERABLE: HTTPS access from anywhere
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Allows access from anywhere
  }

  # VULNERABLE: All outbound traffic allowed
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: Allows all outbound traffic
  }
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Shadow EC2 instance with public IP
resource "aws_instance" "shadow_instance" {
  ami           = "ami-12345678"  # VULNERABLE: Hardcoded AMI
  instance_type = "t3.medium"
  
  # VULNERABLE: Public IP address
  associate_public_ip_address = true
  
  # VULNERABLE: Subnet in public subnet
  subnet_id = aws_subnet.shadow_public_subnet.id
  
  # VULNERABLE: Overly permissive security group
  vpc_security_group_ids = [aws_security_group.shadow_sg.id]
  
  # VULNERABLE: No key pair for SSH access
  # VULNERABLE: No user data for secure configuration
  
  # VULNERABLE: Root volume configuration
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false  # VULNERABLE: No encryption
  }
  
  # VULNERABLE: No tags for tracking
  # VULNERABLE: No cost allocation tags
  # VULNERABLE: No security tags
}

# VULNERABLE: Shadow RDS instance
resource "aws_db_instance" "shadow_db" {
  identifier = "shadow-database"
  
  # VULNERABLE: Publicly accessible database
  publicly_accessible = true
  
  # VULNERABLE: Weak database configuration
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  storage_encrypted    = false  # VULNERABLE: No encryption
  
  # VULNERABLE: Weak credentials
  username = "admin"
  password = "password123"  # VULNERABLE: Hardcoded password
  
  # VULNERABLE: No backup configuration
  backup_retention_period = 0
  backup_window          = ""
  maintenance_window     = ""
  
  # VULNERABLE: No deletion protection
  deletion_protection = false
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Shadow S3 bucket
resource "aws_s3_bucket" "shadow_bucket" {
  bucket = "shadow-data-bucket-12345"
  
  # VULNERABLE: No encryption
  # VULNERABLE: No versioning
  # VULNERABLE: No lifecycle policy
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Public S3 bucket policy
resource "aws_s3_bucket_policy" "shadow_bucket_policy" {
  bucket = aws_s3_bucket.shadow_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWrite"
        Effect    = "Allow"
        Principal = "*"  # VULNERABLE: Allows any principal
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.shadow_bucket.arn}/*"
      },
    ]
  })
}

# VULNERABLE: Shadow IAM role with excessive permissions
resource "aws_iam_role" "shadow_role" {
  name = "shadow-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  
  # VULNERABLE: No tags for tracking
}

# VULNERABLE: Overly permissive IAM policy
resource "aws_iam_role_policy" "shadow_policy" {
  name = "shadow-instance-policy"
  role = aws_iam_role.shadow_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # VULNERABLE: All actions allowed
        Resource = "*"  # VULNERABLE: All resources allowed
      }
    ]
  })
}

# VULNERABLE: Instance profile with excessive permissions
resource "aws_iam_instance_profile" "shadow_profile" {
  name = "shadow-instance-profile"
  role = aws_iam_role.shadow_role.name
}

# VULNERABLE: Output sensitive information
output "shadow_instance_public_ip" {
  value = aws_instance.shadow_instance.public_ip
  # VULNERABLE: Exposing public IP
}

output "shadow_db_endpoint" {
  value = aws_db_instance.shadow_db.endpoint
  # VULNERABLE: Exposing database endpoint
}

output "shadow_bucket_name" {
  value = aws_s3_bucket.shadow_bucket.bucket
  # VULNERABLE: Exposing bucket name
}

# VULNERABLE: No monitoring or alerting
# VULNERABLE: No logging configuration
# VULNERABLE: No backup strategy
# VULNERABLE: No disaster recovery plan
# VULNERABLE: No compliance controls
# VULNERABLE: No security scanning
# VULNERABLE: No vulnerability assessment
