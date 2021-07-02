provider "aws" {
  region = "eu-west-2"
}

#create vpc and specify cidr block

resource "aws_vpc" "Project_VPC" {
cidr_block = "10.0.0.0/16"
tags = {
Name = "Project_VPC"
}
}

# Creating 3 subnets 2 public and 1 private 
resource "aws_subnet" "Project_Pub_SN1" {
  vpc_id     = aws_vpc.Project_VPC.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "eu-west-2a"

  tags = {
    Name = "Project_Pub_SN1"
  }
}

resource "aws_subnet" "Project_Prv_SN" {
  vpc_id     = aws_vpc.Project_VPC.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "eu-west-2b"

  tags = {
    Name = "Project_Prv_SN"
  }
}

resource "aws_subnet" "Project_Pub_SN2" {
  vpc_id     = aws_vpc.Project_VPC.id
  cidr_block = "10.0.3.0/24"
  availability_zone = "eu-west-2c"

  tags = {
    Name = "Project_Pub_SN2"
  }
}


#Create frontEnd Security Group and BackEnd Security Group
resource "aws_security_group" "Project_FrontEnd_SG" {
    description = "Allow TLS inbound traffic"
    vpc_id      = aws_vpc.Project_VPC.id

    ingress {
    description = "http rule"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "https rule"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ssh rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Project_FrontEnd_SG"
  }
}

resource "aws_security_group" "Project_BackEnd_SG" {
    description = "Allow SSH and Mysql inbound traffic"
    vpc_id      = aws_vpc.Project_VPC.id
  ingress {
    description = "mysql rule"
    from_port   = 43
    to_port     = 43
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    description = "ssh rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  tags = {
    Name = "Project_BackEnd_SG"
  }
}

# creating internet gateway for the network 
resource "aws_internet_gateway" "Project_VPC_IGW" {
  vpc_id = aws_vpc.Project_VPC.id

  tags = {
    Name = "Project_VPC_IGW"
  }
}


# Creating the NAT gateway
resource "aws_nat_gateway" "Project_VPC_NG" {
  allocation_id = aws_eip.Project_eip.id
  subnet_id = aws_subnet.Project_Pub_SN1.id
}



#create eip for instance

resource "aws_eip" "Project_eip" {
  instance = aws_instance.Web_App_Server1.id
  #vpc      = true
}


# Output for the EIP
output "Project_eip" {
  description = "Contains the public IP address"
  value       = aws_eip.Project_eip.public_ip
}




# Creating the Route tables
resource "aws_route_table" "Project_VPC_RT_Pub_SN1" {
  vpc_id = aws_vpc.Project_VPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Project_VPC_IGW.id
  }
}

resource "aws_route_table" "Project_VPC_RT_Pub_SN2" {
  vpc_id = aws_vpc.Project_VPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Project_VPC_IGW.id
  }
}


resource "aws_route_table" "Project_VPC_RT_Prv_SN" {
  vpc_id = aws_vpc.Project_VPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Project_VPC_IGW.id
  }
}


#Route table Association
resource "aws_route_table_association" "Project_VPC_RT_Prv_SN" {
  subnet_id      = aws_subnet.Project_Prv_SN.id
  route_table_id = aws_route_table.Project_VPC_RT_Prv_SN.id
}

resource "aws_route_table_association" "Project_VPC_PubRT_PubSN1" {
  subnet_id      = aws_subnet.Project_Pub_SN1.id
  route_table_id = aws_route_table.Project_VPC_RT_Pub_SN1.id
}

resource "aws_route_table_association" "Project_VPC_PubRT_PubSN2" {
  subnet_id      = aws_subnet.Project_Pub_SN2.id
  route_table_id = aws_route_table.Project_VPC_RT_Pub_SN2.id
}


##############################################################################

# Creation of S3 public and private buckets  and the policy for the Mini project
resource "aws_s3_bucket" "Project" {
  bucket = "projectmedia"
  acl    = "public-read"

}


resource "aws_s3_bucket" "Project_bkp" {
  bucket = "projectbkp"
  acl    = "private"
}


resource "aws_s3_bucket_policy" "Project" {
  bucket = "projectmedia"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "Project_policy",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
    "Principal": "*",
      "Action": [
          "s3:GetObject"
          ],
      "Resource":[
          "arn:aws:s3:::projectmedia/*"
      ]
    }
  ]
}
POLICY
}
Creating 
#create RDS database for the back-end
resource "aws_db_instance" "Projectdbinstance" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "8.0.17"
  instance_class       = "db.t2.micro"
  name                 = "Projectdb"
  username             = "cloudhightadmin"
  password             = "Motiva123Logic!"
  #vpc_id      =  aws_vpc.Project_VPC.id
  #vpc_security_group_ids = ["${aws_security_group.Project_BackEnd_SG.id}"]
  #subnet_id      = aws_subnet.Project_Prv_SN.id
  db_subnet_group_name      = "${aws_db_subnet_group.Projectdb_subnet_group.id}"
  vpc_security_group_ids = ["${aws_security_group.Project_BackEnd_SG.id}"]
  skip_final_snapshot       = true
  final_snapshot_identifier = "Ignore"
}

resource "aws_db_subnet_group" "Projectdb_subnet_group" {
  name        = "Projectdb_subnet_group"
  description = "database private groups"
  subnet_ids  = ["${aws_subnet.Project_Prv_SN.id}","${aws_subnet.Project_Pub_SN1.id}", "${aws_subnet.Project_Pub_SN2.id}"]
}


 

##############################################################################################################
resource "aws_s3_bucket" "s3bucket" {
  bucket = "projectmedia"
  acl    = "private"

  tags = {
    Name = "s3bucket"
  }
}

 ######################################################
 # Create Cloudfront distribution 

 locals {
  s3_origin_id = "myS3Origin"
}


resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.s3bucket.bucket_regional_domain_name
    origin_id = local.s3_origin_id
  }
  


  enabled = true
  is_ipv6_enabled = true
  default_root_object = "index.html"

  logging_config {
    include_cookies = false
    bucket = "projectmedia.s3.amazonaws.com"
    

  }



  default_cache_behavior {
    allowed_methods = [
      "DELETE",
      "GET",
      "HEAD",
      "OPTIONS",
      "PATCH",
      "POST",
      "PUT"]
    cached_methods = [
      "GET",
      "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl = 0
    default_ttl = 3600
    max_ttl = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern = "/*"
    allowed_methods = [
      "GET",
      "HEAD",
      "OPTIONS"]
    cached_methods = [
      "GET",
      "HEAD",
      "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers = [
        "Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl = 0
    default_ttl = 86400
    max_ttl = 31536000
    compress = true
    viewer_protocol_policy = "redirect-to-https"
  }

//  # Cache behavior with precedence 1
//  ordered_cache_behavior {
//    path_pattern = "/content/*"
//    allowed_methods = [
//      "GET",
//      "HEAD",
//      "OPTIONS"]
//    cached_methods = [
//      "GET",
//      "HEAD"]
//    target_origin_id = local.s3_origin_id
//
//    forwarded_values {
//      query_string = false
//
//      cookies {
//        forward = "none"
//      }
//    }
//
//    min_ttl = 0
//    default_ttl = 3600
//    max_ttl = 86400
//    compress = true
//    viewer_protocol_policy = "redirect-to-https"
//  }



  restrictions {
    geo_restriction {
      restriction_type = "none"

    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
  
    cloudfront_default_certificate = true
    
  }
}

##############################################################
  #create key-pair

resource "aws_key_pair" "project_key" {
  key_name   = "project_key"
  public_key = file("~/.project/miniprj.pub")
}

################################################################

#Create Ec2-instance, attach key-pair, attach to public-subnet, attach to front-end security group, 
#attach instance profile for iam
#specify the connection type


resource "aws_instance" "Web_App_Server1" {
key_name      = aws_key_pair.project_key.key_name
        subnet_id      = aws_subnet.Project_Pub_SN1.id
ami = "ami-0fc841be1f929d7d1"
iam_instance_profile = "${aws_iam_instance_profile.project_profile.name}"
user_data              = file("wordpress.sh")
instance_type = "t2.micro"
vpc_security_group_ids = ["${aws_security_group.Project_FrontEnd_SG.id}"]
connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/.project/miniprj")
    host        = self.public_ip
  }

tags = {
    Name = "Web_App_Server1"
  }

}

# Creation of Image for instance
resource "aws_ami_from_instance" "project_image" {
  name               = "terraform-project_image"
  source_instance_id = "i-0bc7873cabfb29190"
}

#######################################################################

##################
#Create Application Load Balancer 

resource "aws_lb" "project_Lb" {
  name     = "project-ALB"
  internal = false

  security_groups = [
    "${aws_security_group.ELB_Security.id}",
  ]

  subnets = [aws_subnet.Project_Pub_SN1.id, aws_subnet.Project_Prv_SN.id, aws_subnet.Project_Pub_SN2.id]

  tags = {
    Name = "project-ALB"
  }

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}


####################################################################
resource "aws_alb_listener" "project-listner-80" {
  default_action {
    target_group_arn = aws_lb_target_group.project_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.project_Lb.arn
  port = 80
}

resource "aws_alb_listener" "project-listner-8080" {
  default_action {
    target_group_arn = aws_lb_target_group.project_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.project_Lb.arn
  port = 8080
}


resource "aws_alb_listener" "project-listner-443" {
  default_action {
    target_group_arn = aws_lb_target_group.project_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.project_Lb.arn
  port = 443
  protocol = "HTTP"
  
  
}


#######################################################
#create target group

resource "aws_lb_target_group" "project_Targetgrp" {
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.Project_VPC.id

  load_balancing_algorithm_type = "least_outstanding_requests"

  stickiness {
    enabled = true
    type    = "lb_cookie"
  }

  health_check {
    healthy_threshold   = 2
    interval            = 30
    protocol            = "HTTP"
    unhealthy_threshold = 2
  }

  depends_on = [
    aws_lb.Motiva_Lb
  ]

  lifecycle {
    create_before_destroy = true
  }
}

# Attachment for the Auto Scalling to ALB target group

resource "aws_autoscaling_attachment" "project_AST" {
  autoscaling_group_name = aws_autoscaling_group.project_ASG.id
}

################################################################
#create traffic to ELB through security groups

resource "aws_security_group" "ELB_Security" {
  description = "Allow connection between ALB and target"
  vpc_id      = aws_vpc.Project_VPC.id
}

resource "aws_security_group_rule" "ingress" {

  security_group_id = aws_security_group.ELB_Security.id
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  type              = "ingress"
  cidr_blocks       = ["0.0.0.0/0"]
}




##########################################################
#launch configuration


resource "aws_launch_configuration" "motiva-launch-config" {
  image_id        = "ami-0fc841be1f929d7d1"
  instance_type   = "t2.micro"
  security_groups = ["${aws_security_group.ELB_Security.id}"]
}


##################################################################
#create Auto-scaling Group

resource "aws_autoscaling_group" "Motiva_ASG" {
  launch_configuration = "${aws_launch_configuration.motiva-launch-config.name}"
  vpc_zone_identifier  = [aws_subnet.Project_Pub_SN1.id, aws_subnet.Project_Pub_SN2.id]
  health_check_type    = "ELB"
  min_size = 2
  max_size = 10

  tag {
    key                 = "Name"
    value               = "Motiva-test-asg"
    propagate_at_launch = true
  }
}




###################################################################################################
#creating IAM Roles 

resource "aws_iam_role" "Motiva_IAM_role" {
  name = "Motiva_IAM_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
      tag-key = "tag-value"
  }
}

#To be able to attach this role to Ec2 instance, create instance profile

resource "aws_iam_instance_profile" "Motiva_profile" {
  name = "Motiva_profile"
  role = "${aws_iam_role.Motiva_IAM_role.name}"
}



#Adding IAM Policies to give full access to S3 bucket

resource "aws_iam_role_policy" "s3_Access_policy" {
  name = "s3_Access_policy"
  role = "${aws_iam_role.Motiva_IAM_role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


#create hosted zone
resource "aws_route53_zone" "smartpatientshub_hosted_zone" {
  name = "smartpatientshub.com"
}

#create root domain record in the hosted zone
resource "aws_route53_record" "root_domain_record" {
  zone_id = aws_route53_zone.smartpatientshub_hosted_zone.zone_id
  name    = "smartpatientshub.com"
  type    = "A"
  ttl     = "300"
  records = ["18.135.192.32"]
}


#create alias record for the root domain
resource "aws_route53_record" "alias_domain_record" {
  zone_id = aws_route53_zone.smartpatientshub_hosted_zone.zone_id
  name    = "www.smartpatientshub.com"
  type    = "A"

  alias {
    name                   = "smartpatientshub.com"
    zone_id                = aws_route53_zone.smartpatientshub_hosted_zone.zone_id
    evaluate_target_health = true
  }
}
