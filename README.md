# A10 Networks AWS Cloud Formation Templates Release v1.3.0
Welcome to AWS Cloud Formation Templates 1.3.0 Latest Version.

Thunder® ADCs (Application Delivery Controllers) are high-performance solutions to accelerate and optimize critical applications to ensure delivery and reliability.

AWS Cloud Formation Templates is a custom template to create and configure Thunder using AWS CFT[.json] and Python[.py] scripts.

This template contains several configurations of Thunder which can be applied via box examples provided.AWS Cloud Formation Templates will install Thunder in the AWS cloud environment and configure the Thunder via AXAPI.

## Support Matrix

|        ACOS ADC         | [AWS 1.0.0](https://gitlab.a10networks.com/dev-shared-infra/a10-aws-cft-internal/-/tree/release/v1.0.0) | [AWS 1.1.0](https://gitlab.a10networks.com/dev-shared-infra/a10-aws-cft-internal/-/tree/release/v1.1.0) | [AWS 1.2.0](https://gitlab.a10networks.com/dev-shared-infra/a10-aws-cft-internal/-/tree/feature/SLB-Templates) | [AWS 1.3.0](https://gitlab.a10networks.com/dev-shared-infra/a10-aws-cft-internal/-/tree/feature/Across_HA) |
|:-----------------------:|:------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------:|
|  `ACOS version 6.0.4`   |                                            `No`                                            |                                           `No`                                            |                                           `No`                                            |`Yes`                                            |
|  `ACOS version 6.0.3`   |                                            `No`                                            |                                           `No`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 6.0.2` |                                           `No`                                            |                                           `No`                                            |                                            `Yes`                                            |`Yes`                                            |
|  `ACOS version 6.0.1`   |                                            `No`                                            |                                           `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 6.0.0-p2` |                                           `No`                                            |                                           `Yes`                                            |                                            `Yes`                                            |`Yes`                                            |
| `ACOS version 6.0.0-p1` |                                           `No`                                            |                                            `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 5.2.1-p6` |                                           `Yes`                                            |                                           `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 5.2.1-p5` |                                           `Yes`                                            |                                           `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 5.2.1-p4` |                                           `Yes`                                            |                                            `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |
| `ACOS version 5.2.1-p3` |                                           `Yes`                                            |                                            `Yes`                                            |                                           `Yes`                                            |`Yes`                                            |


## Release Logs

## AWS Cloud Formation Templates-1.3.0

- Added a template for creating new virtual private cloud (VPC) containing six new subnets and two new security groups (SGs) in same or different availability zone in the same region.
- Added template for deploying two vThunder instances in the same or different availability zones, including resources such as three network interface cards, Private IPs (Alien IPs), and Elastic IPs. 
- Added script for HA Across AZs configuration. 

## AWS Cloud Formation Templates-1.2.0

- Support for ACOS v6.0.1, v6.0.2 and v6.0.3
- All template deployment and configuration parameters are separated.
- Added SLB HTTP and Persist Cookie templates. 
- Added Thunder Observability Agent (TOA) support.  
- Added the following new templates:
  1. A10-vThunder-2NIC-1VM
  2. A10-vThunder-3NIC-2VM
  3. A10-vThunder-3NIC-3VM
  4. AUTOSCALE-SERVER
  5. PUBLIC_IP
  6. VPC-SUBNET-NSG


- Added the following configurations for each of the templates:
  1. BASIC-SLB 
  2. CHANGE-PASSWORD 
  3. CONFIG-SLB_ON_BACKEND-AUTOSCALE 
  4. GLM-LICENSE 
  5. HIGH-AVAILABILITY 
  6. HYBRID-CLOUD-GSLB 
  7. SSL-CERTIFICATE


## AWS Cloud Formation Templates-1.1.0

- Support for ACOS 6.0.0-p1 password change.
- Support for ACOS 6.0.0-p2 password change.
- Added the following new templates:
  1. A10-vThunder_ADC-2NIC-1VM 
  2. A10-vThunder_ADC-2NIC-1VM-GLM 
  3. A10-vThunder_ADC-3NIC-2VM-HA 
  4. A10-vThunder_ADC-3NIC-2VM-PVTVIP 
  5. A10-vThunder_ADC-3NIC-2VM-PUBVIP 
  6. A10-vThunder_ADC-3NIC-6VM-2RG-GSLB 


- Added the following configurations for each of the templates:
  1. Password Change 
  2. SSL Certificate 
  3. GLM License 
  4. Server Load Balancer 
  5. High Availability


## AWS Cloud Formation Templates-1.0.0

- vThunder infra setup with different features and combinations.
- vThunder configuration.
- Added the following templates:
  1. A10-vThunder_ADC-2NIC-1VM-GLM 
  2. A10-vThunder_ADC-2NIC-1VM 
  3. A10-vThunder_ADC-3NIC-2VM-HA-GLM-PUBVIP-BACKAUTO 
  4. A10-vThunder_ADC-3NIC-2VM-HA-GLM-PVTVIP 
  5. A10-vThunder_ADC-3NIC-2VM-HA 
  6. A10-vThunder_ADC-3NIC-6VM-2RG-GSLB 
 
- **AWS console**<br>
The pre-requisite to using this option is to download the scripts first by the user, upload script to AWS Cloud Formation console and select parameters on aws. 
For more information on using this option please refer to AWS documentation: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-using-console.html

## How to install Python on Windows:

    1. Download Windows installable from:
        https://www.python.org/downloads/windows/.

    2. After downloading the installer, locate the downloaded file (usually in your Downloads folder) and double-click on it to run it. The installer will open.

    3. Add Python to PATH (Important):

On the installation setup screen, make sure to check the box that says "Add Python x.y to PATH." This is important as it allows you to run Python from the command line without specifying the full path to the Python executable.
  
    4. Install Python:

Click the "Install" button to begin the installation. The installer will copy Python files to your computer.


## How to install Python on MacOs:

    1. Install Python 3 with Homebrew:
	If you prefer to use Python 3 (which is recommended), you can install it using Homebrew. Run the following command:
	 brew install python@3


    2. Verify Python Installation:
	After the installation is complete, verify Python's installation by running:
	 python3 --version

## How to Install Python on Ubuntu:

    1. open the Terminal in Ubuntu by pressing and run the following commands.
	sudo apt update
	sudo apt install python3

    2. Verify Python Installation:

        After the installation is complete, you can verify Python's installation by running:
	python3 --version

## How to deploy vThunder instance using an AWS template with AWS console 

Navigate to the AWS template directory which needs to be applied and follow the below steps.

1. Navigate to AWS Console -> CloudFormation -> Stacks -> Create Stack 
2. Select “Upload a template file”. Choose file for e.g. CFT_TMPL_2NIC_1VM.json 
3. Fill in the fields of parameter. 
4. Go to AWS Console -> CloudFormation-> Stacks-> {stack name} to verify the resources created.

## A10’s vThunder Support Information
Below listed A10’s vThunder vADC (Application Delivery Controller) are tested and supported.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p5, build 114.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p6, build 74.
- 64-bit Advanced Core OS (ACOS) version 6.0.0.

## Release Logs Information
- Automated script to change password after installation.
- Automated scripts to install and configure runbooks.
- Advance support for ACOS version 6.X.X.
## How to verify configuration on Thunder

To verify the applied configuration, follow the below steps:

  1. SSH into the Thunder device using your username and password.
  2. Once connected, enter the following commands:

     1. `enable`

        ![image](https://github.com/smundhe-a10/terraform-provider-thunder/assets/107971633/7e532cee-fa8e-4af7-aa50-da56a24dd4c3)

     3. `show running-config`

        ![image](https://github.com/smundhe-a10/terraform-provider-thunder/assets/107971633/ae37e53d-c650-43f0-b71f-2416f4e5d65a)
     

## How to contribute

If you have created a new example, please save the CFT/Python file with a resource-specific name, such as "AWS_CFT_2NIC_1VM.json" and "AWS_CFT_2NIC_1VM_PARAM.json"

1. Clone the repository.
2. Copy the newly created file and place it under the /examples/resource directory.
3. Create an MR against the master branch.


## Documentation

A10 AWS Cloud Formation template documentation is available below location, 
- AWS : https://documentation.a10networks.com -> Infrastructure as Code (IAC) -> AWS



## Report an Issue

Please raise the issue in the GitHub repository.
Please include the AWS Cloud Formation Templates script that demonstrates the bug and the command output and stack traces will be helpful.


## Support

Please reach out at support@a10networks.com with "a10-aws-CFT-templates" in the subject line.

