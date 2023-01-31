
# PREREQUISITES
    1. Python version Python 3.8.10
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
 

# CFT_TMPL_2NIC_1VM_1.json
	This is cloud formation template to create infrastructure and resources into aws.
   
# CFT_TMPL_2NIC_1VM_CONFIG_SLB_SSL_2.py
     This is vthunder configuration script to configure SLB and SSL.
	 
# CFT_TMPL_2NIC_1VM_CONFIG_SLB_SSL_PARAM.json
     This is vthunder configuration parameter file contains parameters to configure SLB and SSL.
	 
# requirements.txt
     This is list of additional packages list need to install to run configuration script. 
        
# ADDITIONAL FILES
	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of CFT_TMPL_2NIC_1VM_CONFIG_SLB_SSL_2.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	4. server.pem:
		This is sample SSL certificate file. User can replace this certificate with his onw certificate. 
	For more details please follow user guide: CFT_TMPL_2NIC_1VM_USER_GUIDE.docx
			