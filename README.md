# A10 Networks AWS Cloud Formation Templates Release v1.0.0
Welcome to GitHub repository for A10’s CFT templates for AWS cloud. This repository hosts templates for single-click deployment of A10’s vThunder on AWS cloud. 

## What is Cloud Formation Templates (CFT) Template?
CFT template simplifies provisioning and management on AWS. You can create templates for the service or application 
architectures you want and have CFT use those templates for quick and reliable provisioning of the 
services or applications (called “stacks”). You can also easily update or replicate the stacks as needed.This collection 
of sample templates will help you get started with CFT and quickly build your own templates.

## Deployment options for A10's CFT templates in AWS
These CFT templates can be deployed through the AWS Cloud Console. 

- **Deploy to AWS**<br>
This is a single click option which takes the user can customise templates and parameters
and initiating the template deployment. 

- **AWS Console**<br>
The pre-requisite to using this option is to download the scripts first by the user, customise certain parameters
like resource group, VM name, network etc before pasting the script’s content on AWS portal. 
For more information on using this option please refer to AWS documentation.

## A10’s CFT Template Information
A10’s CFT templates listed here are for deploying vThunder ADC (Application Delivery Controller) in different design and configuration namely:
- CFT templates can be found under ./CFT-TEMPLATES.

For more detailed documentation please refer offline documentation within repository or online documentation :
https://documentation.a10networks.com/IaC/CFT/index.html

## A10’s vThunder Support Information
Below listed A10’s vThunder vADC (Application Delivery Controller) are tested and supported.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p5, build 114.
- 64-bit Advanced Core OS (ACOS) version 5.2.1-p6, build 74.

## Release Logs Information
- vThunder infra setup with different feature and combinations.
- vThunder configuration.