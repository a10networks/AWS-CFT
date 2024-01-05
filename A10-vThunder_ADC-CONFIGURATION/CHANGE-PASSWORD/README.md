### Change Password
This configuration script will help to change password of Thunder.

**File**

    1. CHANGE_PASSWORD.py is a python script to configure new password on Thunder instances.
    2. CHANGE_PASSWORD_PARAM.json is a parameter file that contains publicIpList and secret manager name parameters to change passwords.

**Requirements**

    1. Python version Python 3.8.10
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. vThunder instances in running state.
   

**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update CHANGE_PASSWORD_PARAM.json
    3. Execute CHANGE_PASSWORD.py
	    From the Start menu, open cmd and navigate to the A10-vThunder_ADC-CONFIGURATION/CHANGE-PASSWORD folder.	
	    Run the following command from the command prompt:
            python CHANGE_PASSWORD.py

**Additional Files**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of PASSWORD_CHANGE.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix]. 
	4. CHANGE_PASSWORD_UTILS.py:
		This file is used to change the password of deployed vThunder.
	5. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 
	
			