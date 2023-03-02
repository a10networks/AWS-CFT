"""
--------SCRIPT TO CONFIGURE V-THUNDER DEVICE AS A SLB, SSL, GLM --------
Functions:
    [a] Function for SLB Configuration on vthunder
    1. get_auth_token
    2. configure_ethernet
    3. configure_server
    4. configure_service_group
    5. configure_virtual_server

    [b] Function for applying glm license on vthunder
    1. get_appliance_uuid
    2. active_license
    3. configure_glm
    4. glm_request_send

    [c] Function for SSL Configuration on vthunder
    1. ssl_upload

    [d] Function to save configuration to memory
    1. write_memory
"""
import os.path
from logger import logger
import warnings
import json
import requests
import boto3
import base64
import CHANGE_PASSWORD
import getpass

warnings.filterwarnings('ignore')

# host_name of glm portal
host_url = "https://glm.a10networks.com/"


def validate_load_json(ssl_status):
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('CFT_TMPL_2NIC_1VM_GLM_CONFIG_SLB_SSL_GLM_PARAM.json')
        SLB_param_data = json.load(parameter_file)
        if 'parameters' in SLB_param_data:
            if 'stackDetails' not in SLB_param_data['parameters']:
                print("Stack details not provided.")
                return None
            if 'server-list' not in SLB_param_data['parameters']:
                print("server list is not provided.")
                return None
            if 'serviceGroupList' not in SLB_param_data['parameters']:
                print("service group list is not provided.")
                return None
            if 'virtualServerList' not in SLB_param_data['parameters']:
                print("virtual server list is not provided.")
                return None
            if ssl_status:
                if 'sslConfig' in SLB_param_data['parameters']:
                    if 'requestTimeOut' not in SLB_param_data['parameters']['sslConfig']:
                        print("request timeout details not provided.")
                        return None
                    if 'Path' not in SLB_param_data['parameters']['sslConfig']:
                        print("ssl certificate file path not provided.")
                        return None
                    if 'File' not in SLB_param_data['parameters']['sslConfig']:
                        print("certificate name not provided.")
                        return None
                    if 'certificationType' not in SLB_param_data['parameters']['sslConfig']:
                        print("Certification type not provided.")
                        return None
                else:
                    print("ssl configuration details not provided.")
                    return None
        else:
            print("No parameters provided in file.")
            return None
        return SLB_param_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_server_pvt_ip(server_name):
    """
       Function to get private ip of servers
       :param servers:server's tag value
       :return server_pvt_ip :
    """
    pvt_ip = ""
    client = boto3.client('ec2')
    response = client.describe_instances(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [
                    server_name
                ]
            }
        ]
    )
    for reservation in response['Reservations']:
        for interface in reservation["Instances"][0]["NetworkInterfaces"]:
            pvt_ip = interface["PrivateIpAddress"]
    return pvt_ip


def get_interfaces_ids(interfaces_name_tag_values):
    """
    Function to get interface ids of management interface using interface tag
    :param interfaces_name_tag_values:list of management interface tag value
    :return interface_ids :
    """
    interface_ids = []
    for interface in interfaces_name_tag_values:
        EC2_RESOURCE = boto3.client('ec2')
        response = EC2_RESOURCE.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [
                        interface
                    ]
                }
            ]
        )
        if len(response['NetworkInterfaces']) == 1:
            interface_ids.append(response['NetworkInterfaces'][0]["NetworkInterfaceId"])
        else:
            logger.error("Failed to get interfaces ids")
            logger.error(response)
    return interface_ids


def get_vthunder_public_ip(interface_ids):
    """
    Function to get public ip address of an instance using management interface id
    :param interface_ids:
    :return public_ips:
    """
    # create boto3 EC2 client
    public_ips = []
    for nic_id in interface_ids:
        client = boto3.client('ec2')

        # call boto3 describe address api
        response = client.describe_network_interfaces(
            NetworkInterfaceIds=[
                nic_id,
            ]
        )
        # check if elastic ip information is present in response
        if response['NetworkInterfaces']:
            public_ip_instance_id = [response['NetworkInterfaces'][0]['Association']['PublicIp'],
                                     response['NetworkInterfaces'][0]['Attachment']['InstanceId']]
            public_ips.append(public_ip_instance_id)
        else:
            logger.error('Public ip not found for interface id: %s' % nic_id)
    return public_ips


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
        if response.status_code != 200:
            logger.error('Failed to get authorization token from AXAPI')
            logger.error(response.text)
        else:
            authorization_token = json.loads(response.text)["authresponse"]["signature"]
            return authorization_token
    except Exception as e:
        logger.error('Error in authentication token: ', exc_info=True)


def configure_ethernet(base_url, authorization_token):
    """
    This function will configure ethernet
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return:
    AXAPI: /interface/ethernet/<ethernet_number>
    """
    ethernet_number = 1
    url = "".join([base_url, "/interface/ethernet/" + str(ethernet_number)])
    # AXAPI interface url headers
    header = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {"ethernet": {
        "ifnum": 1,
        "action": "enable",
        "ip": {
            "dhcp": 1
        }
    }
    }
    try:
        response = requests.post(
            url, headers=header, data=json.dumps(data), verify=False)

        if response.status_code != 200:
            logger.error("Failed to configure ethernet ip")
            logger.error(response.text)
        else:
            logger.info("configured ethernet 1 ip")
            print("configured ethernet ip")
    except Exception as e:
        logger.error('Error in configuring ethernet: ', exc_info=True)


def configure_server(SLB_param_data, base_url, authorization_token, server_pvt_ip, server_name):
    """
    Function to configure server
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :param server_pvt_ip: private ip of server
    :param server_name: server name
    :return:
    AXAPI: /axapi/v3/slb/server
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    server_details = {}
    for server in SLB_param_data["parameters"]["server-list"]["value"]:
        server_details["name"] = server_name
        server_details['host'] = server_pvt_ip
        server_details['port-list'] = server["port-list"]
        data = {"server": server_details}
        url = "".join([base_url, "/slb/server"])
        try:
            response = requests.post(url, headers=headers,
                                     data=json.dumps(data), verify=False)
            if response.status_code != 200:
                logger.error("Failed to configure server " + server_name)
                logger.error(response.text)
            else:
                logger.info('Configured server ' + server_name)
                print('Configured server ' + server_name)
        except Exception as e:
            logger.error('Error in configuring server: ', exc_info=True)


def configure_service_group(SLB_param_data, base_url, authorization_token, server_name):
    """
    Function to configure service group
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :param server_name: name of server
    :return:
    AXAPI: /axapi/v3/slb/service-group
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/service-group"])
    service_groups = SLB_param_data["parameters"]["serviceGroupList"]["value"]
    for group in service_groups:
        group["member-list"][0]["name"] = server_name
    data = {
        "service-group-list": service_groups
    }
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure service group")
            logger.error(response.text)
        else:
            logger.info("Configured service group")

    except Exception as e:
        logger.error('Error in configuring service group: ', exc_info=True)


def configure_virtual_server(SLB_param_data, base_url, authorization_token):
    """
    Function to configure virtual servers
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :return:
    AXAPI: /axapi/v3/slb/virtual-server
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/virtual-server"])

    virtual_server_ports = SLB_param_data["parameters"]["virtualServerList"]["value"]
    virtual_server = {"name": SLB_param_data["parameters"]["virtualServerList"]["virtual-server-name"], "use-if-ip": 1,
                      "ethernet": 1, "port-list": virtual_server_ports}
    virtual_server_list = [virtual_server]
    data = {
        "virtual-server-list": virtual_server_list
    }
    try:
        response = requests.post(url, headers=headers,
                                 data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure virtual server " +
                         SLB_param_data["parameters"]["virtualServerList"]["virtual-server-name"])
            logger.error(response.text)
        else:
            logger.info("Configured virtual servers")
            print("Configured virtual servers")
    except Exception as e:
        logger.error('Error in configuring virtual servers: ', exc_info=True)


# ------------------------------- GLM Configuration ----------------------


def get_appliance_uuid(base_url, authorization_token):
    """
    Function to get licenses id
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return: host id
    AXAPI: /file/license/oper
    """
    urlUUID = "".join([base_url, "/file/license/oper"])
    # AXAPI header
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    response = requests.get(urlUUID, headers=headers, verify=False)  # body not included
    appliance_id = json.loads(response.text)["license"]['oper']['host-id']
    try:
        if response.status_code != 200:
            logger.error('Failed to get user token from glm API')
            logger.error(response.text)
        else:
            return appliance_id
    except Exception as e:
        logger.error('Error in getting user token: ', exc_info=True)

def active_license(SLB_param_data, appliance_id, activation_token):
    """
     This function will activate licenses
    :param SLB_param_data: parameters loaded from parameter file.
    :param appliance_id: appliance id
    :param activation_token: activation token
    :return:
    API:https://glm.a10networks.com/activations
    """
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "".join(["Basic ", activation_token]),
    }
    data = {"activation": {
        "token": SLB_param_data['parameters']['entitlement_token']['value'],
        "appliance_uuid": appliance_id,
        "version": "4.1 or newer"
    }
    }
    url = "https://glm.a10networks.com/activations"
    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
    try:
        if response.status_code != 201:
            logger.error('License activation failed.')
            logger.error(response.text)
        else:
            print('License activation completed.')
            logger.info('License activation completed.')
    except Exception as e:
        logger.error('Error in activating license: ', exc_info=True)


def configure_glm(SLB_param_data, base_url, authorization_token):
    """
    This function will configure glm
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
        "token": SLB_param_data['parameters']['entitlement_token']['value']
    }
    }
    response = requests.post(url_glm, headers=headers, data=json.dumps(data), verify=False)
    try:
        if response.status_code != 200:
            logger.critical('Failed to configure glm.')
            logger.error(response.text)
        else:
            logger.info('Configure glm.')
            print('Configure glm configuration.')
    except Exception as e:
        logger.error('Error in configuring glm: ', exc_info=True)


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
        if response.status_code != 200:
            logger.critical('failed to send glm license request')
            logger.error(response.text)
        else:
            logger.info('Glm license request sent successfully.')
            print('Glm license request sent successfully.')
    except Exception as e:
        logger.error('Error in sending glm license request: ', exc_info=True)
        


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
    path = SLB_param_data["parameters"]["sslConfig"]["Path"]
    if path is None or path == "":
        print("Please provide the certificate file path")
        logger.error("certificate file path not found")

    certificate_exists = os.path.exists(path)
    if not certificate_exists:
        print("Certificate file is not present on given path")

    file = SLB_param_data["parameters"]["sslConfig"]["File"]
    if file == "" or file is None:
        print("Please provide the certificate file name")
        logger.error("Certificate file name is missing.")
    certification_type = SLB_param_data["parameters"]["sslConfig"]["certificationType"]
    if certification_type == "" or certification_type is None:
        print("Please provide the certificate type")
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
        else:
            logger.info("SSL Configured.")
            print("SSL Configured.")
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
            if response.status_code != 200:
                logger.error("Failed to run write memory command")
                logger.error(response.text)
            else:
                logger.info("Configurations are saved on partition: " + partition)
                print("Configurations are saved on partition: " + partition)
        except Exception as e:
            logger.error('Error in writing to memory : ', exc_info=True)


##########driver code ##########
if __name__ == "__main__":

    # Get user input to apply ssl certificate.
    question = 'Do you want to upload ssl certificate(yes/no)?'
    while True:
        user_input = input(question)
        if user_input.lower() == "yes":
            upload_ssl_cert = True
            break
        elif user_input.lower() == "no":
            upload_ssl_cert = False
            break
        else:
            print("Please select correct input.")
    # Get user input to apply glm configurations.
    question = 'Do you want to configure GLM (yes/no)?'
    while True:
        user_input = input(question)
        if user_input.lower() == "yes":
            glm_configure = True
            break
        elif user_input.lower() == "no":
            glm_configure = False
            break
        else:
            print("Please select correct input.")
    print("--------------------------------------------------------------------------------------------------------------------")

    # Validate and load parameter file data
    SLB_param_data = validate_load_json(upload_ssl_cert)
    if SLB_param_data is not None:
        # get slb server's private IP
        server_name = SLB_param_data["parameters"]["stackDetails"]["value"][0]["stackName"] + "-" + "server"
        server_pvt_ip = get_server_pvt_ip(server_name)
        mngmnt_interfaces_list = []
        # get list of management interface name of both vThunder devices
        for i in SLB_param_data["parameters"]["stackDetails"]["value"]:
            mngmnt_interfaces_list.append(i["stackName"] + "-" + "inst1-mgmt-nic1")
        # get management interface id of vthunder
        mngmnt_interface_ids = get_interfaces_ids(mngmnt_interfaces_list)
        # get public Ip of vThunder Instances
        public_ip_list = get_vthunder_public_ip(mngmnt_interface_ids)
        username = "admin"
        # Base URL of AXAPIs
        base_url = "https://{0}/axapi/v3".format(public_ip_list[0][0])
        # change vThunder's password
        change_password = CHANGE_PASSWORD.VThunderPasswordHandler("admin")
        status = True
        print("Primary conditions for password validation, user should provide the new password according to the "
              "given combination: \n \nMinimum length of 9 characters \nMinimum lowercase character should be 1 \n"
              "Minimum uppercase character should be 1 \nMinimum number should be 1 \nMinimum special character "
              "should be 1 \nShould not include repeated characters \nShould not include more than 3 keyboard "
              "consecutive characters.\n")
        while status:
            vThNewPassword1 = getpass.getpass(prompt="Enter vThunder's new password:")
            vThNewPassword2 = getpass.getpass(prompt="Confirm new password:")
            if vThNewPassword1 == vThNewPassword2:
                count = 0
                for i in range(len(public_ip_list)):
                    status = change_password.changed_admin_password(public_ip_list[i][0], public_ip_list[i][1],
                                                                    vThNewPassword1)
                    if status:
                        count = count + 1
                    if count == len(public_ip_list):
                        status = False
            else:
                print("Password does not match.")
                continue

        print(
            "--------------------------------------------------------------------------------------------------------------------")
        authorization_token = get_auth_token(username, vThNewPassword1, base_url)
        if authorization_token is not None:
            # 1. Invoke configure_ethernet
            configure_ethernet(base_url, authorization_token)
            # 2. Invoke configure_server
            configure_server(SLB_param_data, base_url, authorization_token, server_pvt_ip, server_name)
            # 3. Invoke configure_service_group
            configure_service_group(SLB_param_data, base_url, authorization_token, server_name)
            # 4. Invoke configure_virtual_server
            configure_virtual_server(SLB_param_data, base_url, authorization_token)

            # GLM configuration
            if glm_configure:
                glm_username = SLB_param_data["parameters"]["user_name"]["value"]
                glm_password = SLB_param_data["parameters"]["user_password"]["value"]
                token_string_bytes = (glm_username + ':' + glm_password).encode("ascii")
                base64_bytes = base64.b64encode(token_string_bytes)
                activation_token = base64_bytes.decode("ascii")
                # 1. Invoke get_appliance_uuid
                appliance_id = get_appliance_uuid(base_url, authorization_token)

                # 2. Invoke active_license
                active_license(SLB_param_data, appliance_id, activation_token)

                # 3. Invoke configure_glm
                configure_glm(SLB_param_data, base_url, authorization_token)

                # 4. Invoke glm_request_send
                glm_request_send(base_url, authorization_token)

            if upload_ssl_cert:
                # 1. Invoke SSL Configuration
                ssl_upload(SLB_param_data, base_url, authorization_token)

            # Invoke write_memory
            write_memory(base_url, authorization_token)
        else:
            print("Fails to get authorization token.")
