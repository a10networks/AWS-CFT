**CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP**

# PREREQUISITES
    1. Python version Python 3.8.10
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
 
# CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_2.json
	This is cloud formation template to create infrastructure and resources into aws.
   
# CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_CONFIG_SSL_SLB_HA_GLM_3.py
     This is vthunder configuration script to configure SLB,SSL,GLM and HA.
	 
# CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_CONFIG_SSL_SLB_HA_GLM_PARAM.json
     This is vthunder configuration parameter file contains parameters to configure SLB, SSL, GLM and HA.

# CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_SERVER_PACKAGE_S3_1.py
     This is python script which will upload lambda function code to S3 bucket.

# CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_SERVER_PACKAGE.zip
     This is python script in zip format contains code and dependancies for lambda function.
	 
# requirements.txt
     This is list of additional packages list need to install to run configuration script. 
        
# ADDITIONAL FILES
	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_CONFIG_SSL_SLB_HA_GLM_3.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	4. server.pem:
		This is sample SSL certificate file. User can replace this certificate with his onw certificate.
			