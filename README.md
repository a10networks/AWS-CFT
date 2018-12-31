# AWS CFTs(CloudFormation Template) for A10 vThunder

## Introduction

This is the repository of CFTs for deploying A10 ADC in the AWS environment .
With the one click you will be able to deploy new stack with vThunder .

## What is CFT (CloudFormation Template)

AWS CloudFormation simplifies provisioning and management on AWS. You can create templates for the service or application architectures you want and have AWS CloudFormation use those templates for quick and reliable provisioning of the services or applications (called “stacks”). You can also easily update or replicate the stacks as needed.This collection of sample templates will help you get started with AWS CloudFormation and quickly build your own templates.


## Template information
In the below mentioned CFTs you will be deploying the vThunder and the internet gateway .  VPC , data and management subnets  need to be created before using them in CFTs .
If there is an existing internet gateway for the VPC used in the CFTs please delete internet Gateway before using VPC in the CFT.

Below is the sample topology showing vThunder deployed using the CFT . 


<img src="https://github.com/pareshvn/AWScft/blob/master/Screenshot%202018-11-29%20at%203.57.39%20PM.png"/>

Below are the sample CFTs which can be use to deploy different flavours of vThunder.
Regions need to be selected after clicking on the link .


## Deploy New Stack with 1 Gbps vThunder 

Deploy new stack with with 1 Gbps license vThunder

<a href="https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?templateURL=https://s3.amazonaws.com/pareshn/CFTs/vthunder-hvm-4.1.1-p6-1Gbps.template">  
   <img src="https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png"/></a>


## Deploy New Stack with 500 Mbps vThunder

Deploy new stack with 500 Mbps license vThunder

<a href="https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?templateURL=https://s3.amazonaws.com/pareshn/CFTs/vthunder-hvm-4.1.1-p6-500MBP.template">  
   <img src="https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png"/></a>
   

## Deploy New Stack with BYOL vThunder

Deploy new stack with BYOL vThunder

<a href="https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?templateURL=https://s3.amazonaws.com/pareshn/CFTs/vthunder-hvm-4.1.1-p6-BYOL.template">  
   <img src="https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png"/></a>








<br><br>For sample CFT please <a href="https://github.com/pareshvn/AWScft/blob/master/vthunder-hvm-4.1.1-p6-1Gbps.txt">click here</a> 

More information on cost and licensing please <a href="https://aws.amazon.com/marketplace/seller-profile?id=0cda37b3-aa1a-4c9d-8daf-c396572cc98b">click here</a>. 




