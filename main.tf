# Deliberate IaC Misconfiguration for Gate 4 Validation
resource "aws_security_group" "bad_sg" {
  name        = "insecure-sg"
  description = "Security group with unrestricted SSH ingress"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
