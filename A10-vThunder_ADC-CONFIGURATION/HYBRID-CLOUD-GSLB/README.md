### Global Server Load Balancing (GSLB)
GSLB is a DNS based system that manipulates the DNS response based on the availability of the Thunder. Run two Thunders setup in an Active-Passive architecture so that if one Thunder setup fails, traffic will be sent to the other.

This configuration script will help to configure the GSLB on cross availability zone.

**Files**

    1. HYBRID_CLOUD_CONFIG_GSLB_PARAM.json Parameter file for hybrid cloud configuration with defalut values.
    2. HYBRID_CLOUD_CONFIG_GSLB.py Python script for configuring hybrid cloud configuration in both region.

**Requirement**

    1. Python version Python 3.8.10
    2. AWS account with required permissions
	3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. 3 vThunders instances, each having 3 NIC attched. Deploy below template for this.
        A10-vThunder_CFT-TEMPLATES/A10-vThunder-3NIC-3VM/CFT_TMPL_3NIC_3VM.json

**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update HYBRID_CLOUD_CONFIG_GSLB_PARAM.json
    3. Execute HYBRID_CLOUD_CONFIG_GSLB.py
	    From the Start menu, open cmd and navigate to the A10-vThunder_ADC-CONFIGURATION/HYBRID-CLOUD-GSLB folder.	
	    Run the following command from the command prompt:
            python HYBRID_CLOUD_CONFIG_GSLB.py

**Additional Files**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of HYBRID_CLOUD_CONFIG_GSLB.py
	2. credentials:
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add aws_access_key_id and aws_secret_access_key in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	3. config:
		User need to add region in this file and copy same to C:\Users\<USERNAME>\.aws  folder [For windows].
		User need to add region in this file and copy same to ~/.aws  folder [For linux, macOS, Unix].
	4. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 
