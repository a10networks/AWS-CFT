"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SSL --------
Functions:
    [a] Function for SSL Configuration on vthunder
    1. ssl_upload
    [b] Function to save configuration to memory
    1. write_memory
"""
import os.path
from logger import logger
import warnings
import json
import requests
import boto3
import getpass

warnings.filterwarnings('ignore')


def validate_load_json(ssl_status):
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('SSL_CONFIG_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'publicIpList' not in SLB_data['parameters']:
                print("Public ip List is not provided.")
                return None
            if ssl_status:
                if 'sslConfig' in SLB_data['parameters']:
                    if 'requestTimeOut' not in SLB_data['parameters']['sslConfig']:
                        print("request timeout details not provided.")
                        return None
                    if 'path' not in SLB_data['parameters']['sslConfig']:
                        print("ssl certificate file path not provided.")
                        return None
                    if 'file' not in SLB_data['parameters']['sslConfig']:
                        print("certificate name not provided.")
                        return None
                    if 'certificationType' not in SLB_data['parameters']['sslConfig']:
                        print("Certification type not provided.")
                        return None
                else:
                    print("ssl configuration details not provided.")
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
     function to logout vthunder session
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
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
            print("Successfully logged out from vThunder.")
            return True
        else:
            logger.error('Failed to logout vThunder')
            logger.error(response.text)
            return False
    except Exception as e:
        logger.error(e)
        return False


def ssl_upload(SLB_param_data, base_url, authorization_token):
    """
    Function to configure SSL
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization_token
    :return:
    AXAPI:/file/ssl-cert
    """
    url = "".join([base_url, "/file/ssl-cert"])
    # Get request timeout
    timeout = SLB_param_data["parameters"]["sslConfig"]["requestTimeOut"]
    path = SLB_param_data["parameters"]["sslConfig"]["path"]
    if path is None or path == "":
        print("Please provide the certificate file path")
        logger.error("certificate file path not found")
    certificate_exists = os.path.exists(path)
    if not certificate_exists:
        print("Certificate file is not present on given path")
    file = SLB_param_data["parameters"]["sslConfig"]["file"]
    if file == "" or file is None:
        print("Please provide the certificate file name")
        logger.error("Certificate file name is missing.")
    certification_type = SLB_param_data["parameters"]["sslConfig"]["certificationType"]
    if certification_type == "" or certification_type is None:
        print("Please provide the certificate type")
        logger.error("Certificate type is missing.")
    payload = {'json': '''{
    "ssl-cert": {
    "file": "%s" ,
    "file-handle":"%s",
    "certificate-type": "%s",
    "action": "import"
    }
    }''' % (file, path.split("/")[-1], certification_type)}

    files = [
        ('file', ('server.pem', open(path, 'rb'), 'application/octet-stream'))
    ]
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        "Authorization": "".join(["A10 ", authorization_token])
    }
    try:
        response = requests.post(
            url, headers=headers, data=payload, files=files, verify=False, timeout=timeout)
        if response.status_code != 204 and response.status_code != 200:
            logger.error("Failed to configure SSL certificate")
            print("Failed to configure SSL certificate")
        else:
            logger.info("SSL Configured.")
            print("Successfully configured SSL.")
    except Exception as e:
        logger.error('Error in configuring SSL : ', exc_info=True)


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
    SLB_param_data = validate_load_json(True)
    # get public Ip of vThunder Instances
    public_ip = SLB_param_data["parameters"]["publicIpList"]
    public_ip_list = []
    for i in public_ip:
        j = i.replace(' ', '')
        public_ip_list.append(j)
    for vth in range(len(public_ip_list)):
        username = "admin"
        base_url = "https://"+public_ip_list[vth]+"/axapi/v3"
        print("Configuring vThunder with ip " + public_ip_list[vth])
        vThNewPassword1 = getpass.getpass(prompt="Enter vThunder Password:")
        authorization_token = get_auth_token(username, vThNewPassword1, base_url)
        if authorization_token:
            # SSL configuration
            ssl_upload(SLB_param_data, base_url, authorization_token)
            # 1. Invoke write_memory
            write_memory(base_url, authorization_token)
            # 2. Logout from current session
            vth_logout(base_url, authorization_token)
            print(
                "--------------------------------------------------------------------------------------------------------------------")
        else:
            print("Fails to get authorization token.")
