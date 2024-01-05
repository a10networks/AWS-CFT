### A10 License (GLM)
After deploying the Thunder instance, you can apply GLM license to the Thunder instance.

**Files**

    1. GLM_CONFIG_PARAM.json This file contains the entitlement token and Thunder ip user name details.
    2. GLM_CONFIG.py Python script to configure GLM on Thunder instances. 

**Requirements**

    1. Python version Python 3.8.10
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. GLM license
    5. vThunder instances in running state.

**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update GLM_CONFIG_PARAM.json
    3. Execute GLM_CONFIG.py
	    From the Start menu, open cmd and navigate to the A10-vThunder_ADC-CONFIGURATION/GLM-LICENSE folder.	
	    Run the following command from the command prompt:
            python GLM_CONFIG.py

**Additional Files**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of GLM_CONFIG.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	4. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 

			
