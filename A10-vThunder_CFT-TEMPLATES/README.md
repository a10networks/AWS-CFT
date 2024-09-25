# PREREQUISITES
    1. AWS account with required permissions.

# A10-vThunder-2NIC-1VM
	This is cloud formation template will creates 1 vThunder instance with 2 NIC attached into AWS cloud.

# A10-vThunder-3NIC-2VM
	It contains 2 cloud formation templates -
    1. CFT_TMPL_3NIC_2VM - This cloud formation template will create two vThunder instances, each with three NICs, all within the same Availability Zone in AWS Cloud.
    2. CFT_TMPL_3NIC_2VM_Across_AZ_HA - This cloud formation template will create two vThunder instances, each with three NICs, distributed across different Availability Zones in the AWS cloud.

# A10-vThunder-3NIC-3VM
	This cloud formation template creates three vThunder instances with three NICs attached in the AWS cloud.

# VPC-SUBNET-NSG
    It contains 2 cloud formation templates -
    1. CFT_TMPL_VIRTUAL_PRIVATE_COMPONENTS - This cloud formation template will create one VPC, three subnets, and two security groups.
    2. CFT_TMPL_VIRTUAL_PRIVATE_COMPONENTS_ACROSS_AZ_HA - This cloud formation template creates 1 VPC, 6 Subnets, and 2 Security groups in same or different Availability Zone.

# PUBLIC-IP
    This is cloud formation template will creates 3 Elastic Public IP.