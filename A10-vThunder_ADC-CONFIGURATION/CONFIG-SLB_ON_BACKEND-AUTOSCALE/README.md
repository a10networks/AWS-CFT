### Backend AutoScale
This configuration script will help to configure the SLB for server backend autoscale group.

**Files**
	
    1. CFT_TMPL_AUTOSCALE_SERVER.json this cloud formation template will create ASG, Event bridge and Lambda function.
    2. AUTOSCALE_SERVER_S3_UPLOAD_1.py will create a S3 bucket and upload the AUTOSCALE_SERVER_PACKAGE.zip to S3 bucket.
    3. AUTOSCALE_SERVER.json is used to delpoy Lambda function, Event hub and AutoScale Group with 0 servers.
    4. AUTOSCALE_SERVER_PARAM.json This file contains the name of lambda function, autoscaling group name, desired capacity of autoscaling and port list.
    5. AUTOSCALE_SERVER_ASG_LAMBDA_UPDATE_2.py this file updates the lambda function.

**Requirements**

    1. Python version Python3
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. Lambda IAM Role with lambda execution permision.
	5. Secret Manger
		- For AWS Credentials
		- For vThunder Credentials
	6. vThunder/vThunders with SLB configuration.
    7. Update vThunder Secret manager credentials by executing below script
        Execute CHANGE_PASSWORD.py

**Execution Step**

    1. Execute A10-vThunder_ADC-CONFIGURATION/CONFIG-SLB_ON_BACKEND-AUTOSCALE/AUTOSCALE_SERVER_S3_UPLOAD_1.py file
            Uploads zip file in new or existing S3 bucket which will be used by lambda function to add or remove backend servers.

    2. Deploy A10-vThunder_CFT-TEMPLATES/AUTOSCALE-SERVER/CFT_TMPL_AUTOSCALE_SERVER.json
            Created Resources:
                - Lambda function
                - Event hub
                - AutoScale Group with 0 servers 
        
    3. Execute A10-vThunder_ADC-CONFIGURATION/CONFIG-SLB_ON_BACKEND-AUTOSCALE/AUTOSCALE_SERVER_ASG_LAMBDA_UPDATE_2.py
            Updates Port-List in lambda function env variables
            Updates instance count from 0 to 1 in autoscale group.
    
**Additional Files**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of AUTOSCALE_SERVER_S3_UPLOAD_1.py and AUTOSCALE_SERVER_ASG_LAMBDA_UPDATE_2.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
		4. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 
	4. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 


			