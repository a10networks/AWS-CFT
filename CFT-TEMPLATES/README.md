# A10 Networks AWS Cloud Formation Templates Release v1.0.0
These Cloudformation templates can be deployed through the AWS console.

- **AWS console**<br>
The pre-requisite to using this option is to download the scripts first by the user, upload script to AWS Cloud Formation console and select parameters on aws. 
For more information on using this option please refer to AWS documentation: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-using-console.html

##Global License Manager (GLM)
For all A10 licenses, GLM (Global License Manager) is the authoritative service. 
All A10 products conform with license and licensing policies dictated by GLM. 
GLM is available at https://glm.a10networks.com. 

# A10’s Cloud Formation Template Information
A10’s AWS CFT templates listed here are for deploying vThunder ADC (Application Delivery Controller) in different design and configuration namely:

- Deploying vThunder ADC in AWS - 2 NICs(1 Management + 1 Data) - 1 VM **<br>
      - *BYOL(Bring Your Own License)*<br>
      - *1 VM*<br>
      - *SLB (vThunder Server Load Balancer)*<br>
      - *SSL (SSL Certification)*<br>
- Deploying vThunder ADC in AWS - 2 NICs(1 Management + 1 Data) - 1 VM - GLM**<br>
      - *BYOL(Bring Your Own License)*<br>
      - *1 VM*<br>
      - *SLB (vThunder Server Load Balancer)*<br>
      - *SSL (SSL Certification)*<br>
      - *GLM (Auto apply A10 license)*<br>
- Deploying vThunder ADC in AWS - 3 NICs(1 Management + 2 Data) - 2VM - HA**<br>
      - *BYOL(Bring Your Own License)*<br>
      - *2 VM*<br>
      - *HIGH AVAILABILITY (Auto swithover with another available VM)*<br>
      - *SLB (vThunder Server Load Balancer)*<br>
      - *SSL (SSL Certification)*<br>
- Deploying vThunder ADC in AWS - 3 NICs(1 Management + 2 Data) - 2VM - HA - GLM - PVTVIP**<br>
      - *BYOL(Bring Your Own License)*<br>
      - *2 VM*<br>
      - *HIGH AVAILABILITY (Auto swithover with another available VM)*<br>
      - *VIP (Private Interface)*<br>
      - *SLB (vThunder Server Load Balancer)*<br>
      - *SSL (SSL Certification)*<br>
      - *GLM (Auto apply A10 license using global license manager)*<br>
- Deploying vThunder ADC in AWS - 3 NICs(1 Management + 2 Data) - 2 VM - HA - GLM - PUBVIP - BACKAUTO**<br>
      - *BYOL(Bring Your Own License)*<br>
      - *2 VM*<br>
      - *HIGH AVAILABILITY (Auto swithover with another available VM)*<br>
      - *VIP (Public Interface)*<br>
      - *BACKEND SERVER AUTOSCALE (Webhook to configure vThunder on web servers auto scaling)*<br>
      - *GLM (Auto apply A10 license using global license manager)*<br>
      - *SLB (vThunder Server Load Balancer)*<br>
      - *SSL (SSL Certification)*<br>
- Deploying vThunder ADC in AWS - 3 NICs(1 Management + 2 Data) - 6VM(Three in each region) - 2RG(Region) - GSLB**<br>
      - *BYOL(Bring Your Own License)*<br>
      - *3 VM in each region*<br>
      - *2 Region*<br>
      - *GSLB (vThunder - Global Server Load Balancer for traffic routing across region.)*<br>

For more detailed documentation please refer offline documentation within repository or online documentation :
https://documentation.a10networks.com/IaC/CFT/index.html

## A10’s vThunder Support Information
Below listed A10’s vThunder vADC (Application Delivery Controller) are tested and supported.
- 64-bit Advanced Core OS (ACOS) version 5.2.0, build 155.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p5, build 114.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p6, build 74.

## Release Logs Information
- vThunder infra setup with different feature and combinations.
- vThunder configuration.
