"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SLB, SSL,GLM, HA --------
Functions:
    [a] Function for applying glm license on vthunder
    1. configure_glm
    2. glm_request_send

    [b] Function to save configuration to memory
    1. write_memory
"""


from logger import logger
import warnings
import json
import requests
import getpass

warnings.filterwarnings('ignore')


def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('GLM_CONFIG_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'publicIpList' not in SLB_data['parameters']:
                print("public ip is not provided.")
                return None
        else:
            print("No parameters provided in file.")
            return None
        return SLB_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_auth_token(username, password, base_url):
    """
    Function to get authorization token.
    :param username: username for vthunder instance
    :param password: password of vthunder
    :param base_url: vthunder base url to access axapi
    :return: Authorization token
    AXAPI: /axapi/v3/auth
    """
    # AXAPI header
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    # AXAPI Auth url json body
    data = {"credentials": {
        "username": username,
        "password": password
    }
    }
    url = "".join([base_url, "/auth"])
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)
        if response.status_code == 200:
            authorization_token = json.loads(response.text)["authresponse"]["signature"]
            return authorization_token
        else:
            logger.error('Failed to get authorization token from AXAPI')
            print('Failed to get authorization token from AXAPI')

    except Exception as e:
        logger.error('Error in authentication token: ', exc_info=True)


def vth_logout(base_url, authorization_token):
    """
    logout vthunder session
    :return 200
    """
    url = f"{base_url}/logoff"
    payload = {}

    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }

    try:
        response = requests.request("GET", url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            print("Succsesfully logged out from vThunder.")
            return True
        else:
            logger.error('Failed to logout vThunder')
            logger.error(response.text)
            return False

    except Exception as e:
        logger.error(e)
        return False

# ------------------------------- GLM Configuration ----------------------


def configure_primary_dns(glm_param_data, base_url, authorization_token):
    """
    This function will configure primary dns
    :param base_url: vthunder base url to access axapi
    :param authorization_token: Authorization token
    :return:
    AXAPI:/ip/dns/primary
    """
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    dns = glm_param_data["parameters"]["dns"]["value"]
    data = {"primary": {
        "ip-v4-addr": dns
    }
    }
    urlDNS = "".join([base_url, "/ip/dns/primary"])
    try:
        response = requests.post(urlDNS, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            print('Successfully configured primary DNS.')
            logger.info('Configured primary dns')
        else:
            logger.error('Failed to configure primary dns')
            logger.error(response.text)

    except Exception as e:
        logger.error('Error in configuring primary dns : ', exc_info=True)


def configure_glm(glm_param_data, base_url, authorization_token):
    """
    This function will configure
    :param glm_param_data: parameter data
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return:
    AXAPI: /glm
    """
    url_glm = "".join([base_url, "/glm"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    data = {"glm": {
        "use-mgmt-port": 1,
        "enable-requests": 1,
        "token": glm_param_data['parameters']['entitlement_token']['value']
    }
    }
    response = requests.post(url_glm, headers=headers, data=json.dumps(data), verify=False)
    try:
        if response.status_code == 200:
            logger.info('Successfully configured GLM Entitlement token in vthunder.')
            print('Successfully configured GLM Entitlement token in vthunder.')
        else:
            logger.critical('Failed to configure GLM Entitlement token in vthunder.')
            logger.error(response.text)
    except Exception as e:
        logger.error('Error in configuring glm Entitlement token in vthunder: ', exc_info=True)


def glm_request_send(base_url, authorization_token):
    """
     This function will send request for glm license
     AXAPI: /glm/send
     :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return:
    """
    url_glm_send = "".join([base_url, "/glm/send"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    data = {"send": {
        "license-request": 1
    }
    }
    response = requests.post(url_glm_send, headers=headers, data=json.dumps(data), verify=False)
    try:
        if 'ERROR' in response.json()['response']['msg']:
            logger.critical('failed to send glm license request')
            logger.error(response.text)
            return False
        else:
            logger.info('Successfully sent Glm license request.')
            print('GLM license request sent successfully.')
            return True
    except Exception as e:
        logger.error('Error in sending glm license request: ', exc_info=True)


def write_memory(base_url, authorization_token):
    """
    Function to save configurations on active partition
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :return:
    AXAPI: /axapi/v3/active-partition
    AXAPI: /axapi/v3//write/memory
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/active-partition"])

    response = requests.get(url, headers=headers, verify=False)
    partition = json.loads(response.text)['active-partition']['partition-name']
    if partition is None:
        print("Failed to get partition name")
        logger.error("Failed to get partition name")
    else:
        url = "".join([base_url, "/write/memory"])
        data = {
            "memory": {
                "partition": partition
            }
        }
        try:
            response = requests.post(url, headers=headers,
                                     data=json.dumps(data), verify=False)
            if response.status_code == 200:
                logger.info("Configurations are saved on partition: " + partition)
                print("Configurations are saved on partition: " + partition)
            else:
                logger.error("Failed to run write memory command")
                print("Failed to run write memory command")

        except Exception as e:
            logger.error('Error in writing to memory : ', exc_info=True)


# ------------------------------- driver code ----------------------
if __name__ == "__main__":
    # Validate and load parameter file data
    glm_param_data = validate_load_json()
    if glm_param_data:
        # get public Ip of vThunder Instances
        public_ip = glm_param_data["parameters"]["publicIpList"]
        public_ip_list = []
        for i in public_ip:
            j = i.replace(' ', '')
            public_ip_list.append(j)
        for vth in range(len(public_ip_list)):
            username = "admin"
            base_url = "https://" + public_ip_list[vth] + "/axapi/v3"
            print("Configuring vThunder with ip " + public_ip_list[vth])
            vth_password = getpass.getpass(prompt="Enter vThunder password:")
            authorization_token = get_auth_token(username, vth_password, base_url)
            # if authorization token is valid
            if authorization_token:

                # 1. Invoke configure_primary_dns
                configure_primary_dns(glm_param_data, base_url, authorization_token)

                # 2.Configure_glm into Thunder
                configure_glm(glm_param_data, base_url, authorization_token)

                # 3.GLM_request_send
                glm = glm_request_send(base_url, authorization_token)

                if not glm:
                    print("Failed to activate License, invalid entitlement token.", glm_param_data['parameters']['entitlement_token']['value'])

                # 4. Invoke write_memory
                write_memory(base_url, authorization_token)

                # 5. Logout from current session
                vth_logout(base_url, authorization_token)

                print(
                    "--------------------------------------------------------------------------------------------------------------------")
            else:
                print("Fails to get authorization token.")
