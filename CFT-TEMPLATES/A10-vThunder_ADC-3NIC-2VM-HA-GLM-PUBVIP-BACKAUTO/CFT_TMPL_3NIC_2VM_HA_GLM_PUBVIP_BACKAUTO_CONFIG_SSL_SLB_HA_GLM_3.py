"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SLB, SSL, GLM, HA--------
Functions:
    [a] Function for SLB Configuration on vthunder
    1. get_auth_token
    2. configure_ethernet
    3. configure_virtual_server

    [b] Function for SSL Configuration on vthunder
    1. ssl_upload

    [c] Function for applying glm license on vthunder
    1. get_appliance_uuid
    2. active_license
    3. configure_primary_dns
    4. configure_glm
    5. glm_request_send

    [d] Function to configure HA
    1. ip_route_config
    2. vrrp_a_config
    3. terminal_timeout_config
    4. vrrp_a_rid_config
    5. peer_group_config

    [e] Function to save configuration to memory
    1. write_memory
"""
import os.path
from logger import logger
import warnings
import json
import requests
import base64
import boto3
import CHANGE_PASSWORD
import getpass

warnings.filterwarnings('ignore')


def validate_load_json(upload_ssl_cert):
    """
    This function will validate and load parameter file's contents.
    :param: upload_ssl_cert : user_choice for ssl_certificate upload
    :param: glm_configure : user_choice for glm configuration
    :return: slb_parameter files contents
    """
    try:
        parameter_file = open('CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_CONFIG_SSL_SLB_HA_GLM_PARAM.json')
        SLB_param_data = json.load(parameter_file)
        if 'parameters' in SLB_param_data:
            if 'stackDetails' not in SLB_param_data['parameters']:
                print("Stack details not provided.")
                return None
            if 'desiredCapacity' not in SLB_param_data['parameters']:
                print("auto scale desired capacity is not provided.")
                return None
            if 'serviceGroup' not in SLB_param_data['parameters']:
                print('service group details not provided.')
                return None
            if 'dns' not in SLB_param_data['parameters']:
                print("dns details not provided.")
                return None
            if upload_ssl_cert:
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


def update_secret(secret_name, vThNewPassword):
    """
    Function to update secret manager and store vThunder password
    :param secret_name: Secret Manager name
    :param vThNewPassword: vThunder password
    :return:
    """
    secret_string = {"vThPassword": vThNewPassword}
    client = boto3.client('secretsmanager')
    response = client.put_secret_value(
        SecretId=secret_name,
        SecretString=json.dumps(secret_string),
    )


def get_lambda_function(lambda_function_name):
    client = boto3.client('lambda')
    response = client.get_function(
        FunctionName=lambda_function_name,
    )
    aws_region = response["Configuration"]["Environment"]["Variables"]["Region"]
    secret_manager = response["Configuration"]["Environment"]["Variables"]["AWSSecretManagerName"]
    return aws_region, secret_manager


def update_lambda_env_variables(secret_manager, function_name, mngmntnic1, mngmntnic2, port_list, aws_region,
                                stackname):
    """
        Function update lambda environment variables
        :param secret_manager: AWS secret manager name
        :param function_name : lambda function_name
        :param mngmntnic1 : management network interface id of vthunder 1
        :param mngmntnic2 : management network interface id of vthunder 2
        :param port_list : port list
        :param aws_region: aws region name
        :param stackname: stack name
    """
    client = boto3.client('lambda')
    response = client.update_function_configuration(
        FunctionName=function_name,
        Environment={
            'Variables': {
                'AWSSecretManagerName': secret_manager,
                'Region': aws_region,
                'vThunder1MgmtNICID': mngmntnic1,
                'vThunder2MgmtNICID': mngmntnic2,
                'PortList': port_list,
                'StackName': stackname

            }
        }
    )


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
        if response['NetworkInterfaces'] is not None:
            interface_ids.append(response['NetworkInterfaces'][0]["NetworkInterfaceId"])
        else:
            print("Failed to get interfaces ids")
            logger.error("Failed to get interfaces ids")
    return interface_ids


def get_vthunder_public_ip(interface_ids):
    """
    Function to get public ip address of an instance using management interface id
    :param interface_ids:interface id list
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


def get_pvt_ips(instance_id):
    response = boto3.client('ec2').describe_instances(
        InstanceIds=[
            instance_id[1],
        ],
    )
    pvt_ips = []
    sec_pvt_ips = []
    for reservation in response['Reservations']:
        for interface in reservation["Instances"][0]["NetworkInterfaces"]:
            pvt_ips.append(interface["PrivateIpAddress"])
        for ii in range(len(reservation["Instances"][0]["NetworkInterfaces"])):
            for i in reservation["Instances"][0]["NetworkInterfaces"][ii]["PrivateIpAddresses"]:
                sec_pvt_ips.append(i["PrivateIpAddress"])
    sec_pvt_ips = [i for i in sec_pvt_ips if i not in pvt_ips]
    return pvt_ips, sec_pvt_ips


def get_ftp_server(server_name):
    """
        Function to get ftp server details.
        :param server_name: ftp server name
        :return: server_public_ip, server_id
        """
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
    server_id = ""
    server_ip = 0
    for instances in response['Reservations']:
        for instance in instances['Instances']:
            if instance['State']['Name'] == "running":
                server_id = instance["InstanceId"]
                server_ip = instance["PublicIpAddress"]
    return server_ip, server_id


def aws_accesskey_upload(base_url, authorization_token, ftp_server_ip):
    """
    Function to configure AWS Access keys to vThunder
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization_token
    :param ftp_server_ip: public ip of ftp server
    :return:
    AXAPI:/admin/admin/aws-accesskey
    """
    url = "".join([base_url, "/admin/admin/aws-accesskey"])
    file_url = "http://" + ftp_server_ip + "/aws_access_key.txt"
    payload = {
        "aws-accesskey": {
            "import": 1,
            "use-mgmt-port": 1,
            "file-url": file_url
        }
    }
    header = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(
            url, headers=header, data=json.dumps(payload), verify=False)
        if response.status_code != 204 and response.status_code != 200:
            logger.error("Failed to load aws access key")
        else:
            logger.info(response.text)
            print("AWS access key uploaded to vThunder.")
    except Exception as e:
        logger.error('Error in uploading AWS access key: ', exc_info=True)


def delete_ftp_server(ftp_server_id):
    """
    Function to delete FTP server.
    :param ftp_server_id: FTP server instance id
    """
    ec2 = boto3.resource('ec2')
    instance = ec2.Instance(ftp_server_id)
    instance.terminate()


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


# ------------------------------- SLB Configuration ----------------------
def configure_ethernet(base_url, authorization_token):
    """
    This function will configure ethernet
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return:
    AXAPI: /interface/ethernet/<ethernet_number>
    """
    ethernet_numbers = 2
    for ethernet in range(1, ethernet_numbers + 1):
        url = "".join([base_url, "/interface/ethernet/" + str(ethernet)])
        # AXAPI interface url headers
        header = {
            "Authorization": "".join(["A10 ", authorization_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        data = {"ethernet": {
            "ifnum": ethernet,
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
                print("Failed to configure ethernet ip")
            else:
                logger.info("configured ethernet 1 ip")
                print("configured ethernet ip")
        except Exception as e:
            logger.error('Error in configuring ethernet: ', exc_info=True)


def configure_service_group(SLB_param_data, base_url, authorization_token):
    """
    Function to configure service group
    :param SLB_param_data: parameters loaded from parameter file.
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :return:
    AXAPI: /axapi/v3/slb/service-group
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/service-group"])
    service_groups = SLB_param_data["parameters"]["serviceGroup"]["value"]
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
            print("Configure service group")
    except Exception as e:
        logger.error('Error in configuring service group: ', exc_info=True)
        logger.error(e)


def configure_virtual_server(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips):
    """
    Function to configure virtual servers
    :param base_url: Base url of AXAPI
    :param authorization_token: authorization token
    :param vThunder1_sec_ips : vThunder1's secondary private ips
    :return:
    AXAPI: /axapi/v3/slb/virtual-server
    """
    headers = {
        "Authorization": "".join(["A10 ", authorization_token]),
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    url = "".join([base_url, "/slb/virtual-server"])
    virtual_server_ip = [ip for ip in vThunder1_sec_ips if ip.split(".")[2] == "2"][0]
    virtual_server_ports = SLB_param_data["parameters"]["virtualServerList"]["value"]
    virtual_server = {"name": SLB_param_data["parameters"]["virtualServerList"]["virtual-server-name"],
                      "ip-address": virtual_server_ip,
                      "port-list": virtual_server_ports}
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


# ------------------------------- SSL Configuration ----------------------
def ssl_upload(SLB_param_data, base_url, authorization_token):
    """
    Function to configure SSL
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
        logger.error("Certificate file is not present on given path")

    file = SLB_param_data["parameters"]["sslConfig"]["File"]
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
            print("Failed to configure SSL certificate")
            logger.error(response.text)
        else:
            logger.info("SSL Configured.")
            print("SSL Configured.")
    except Exception as e:
        logger.error('Error in configuring SSL : ', exc_info=True)


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


def configure_primary_dns(SLB_param_data, base_url, authorization_token):
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
    dns = SLB_param_data["parameters"]["dns"]["value"]
    data = {"primary": {
        "ip-v4-addr": dns
    }
    }
    urlDNS = "".join([base_url, "/ip/dns/primary"])
    response = requests.post(urlDNS, headers=headers, data=json.dumps(data), verify=False)
    try:
        response = requests.post(urlDNS, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error('Failed to configure primary dns')
            logger.error(response.text)
        else:
            print('Configured primary dns ')
            logger.info('Configured primary dns')
    except Exception as e:
        logger.error('Error in configuring primary dns : ', exc_info=True)


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
            logger.info('configure glm.')
            print('configure glm.')
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


# ------------------------------- HA Configuration ----------------------
def ip_route_config(SLB_param_data, base_url, authorization_token):
    """
    This function will configure the IP route.
    AXAPI: /ip/route/rib
     :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :return:
    """
    url = ''.join([base_url, "/ip/route/rib"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    rib_list = SLB_param_data['parameters']['rib-list']
    data = {
        'rib-list': rib_list
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error('Failed to configured IP Route')
            logger.error(response.text)
        else:
            logger.info("Successfully Configured IP route")
            print("Successfully Configured IP route")
    except Exception as exp:
        logger.error(exp)


def vrrp_a_config(SLB_param_data, base_url, authorization_token, device_id):
    """
    This function will configure the vrrp.
    AXAPI: /vrrp-a/common
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :param device_id:device id
    :return:
    """
    url = ''.join([base_url, "/vrrp-a/common"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    set_id = SLB_param_data['parameters']['vrrp-a']['set-id']
    data = {
        "common": {"device-id": device_id,
                   "set-id": set_id,
                   "action": "enable"
                   }
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure Vrrp A common configuration'")
            logger.error(response.text)
        else:
            print('Configured Vrrp A common configuration')
            logger.info('Configured Vrrp A common configuration')
    except Exception as exp:
        logger.error(exp)


def terminal_timeout_config(SLB_param_data, base_url, authorization_token):
    """
        This function will configure terminal timeout.
        AXAPI: /terminal
        :param base_url: vthunder base url to access axapi
        :param authorization_token: authorization token
        :return:
        """
    url = ''.join([base_url, "/terminal"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    timeout = SLB_param_data['parameters']['terminal']['idle-timeout']
    data = {
        "terminal": {"idle-timeout": timeout}
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure idle timeout.")
            logger.error(response.text)
        else:
            logger.info('Configured idle timeout')
            print('Configured idle timeout')
    except Exception as exp:
        logger.error(exp)


def vrrp_a_rid_config(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips, index):
    """
    This function will configure vrrp rid.
    AXAPI: /vrrp-a/vrid
    :param base_url: vthunder base url to access axapi
    :param authorization_token: authorization token
    :param vThunder1_sec_ips : secondary private ips list of vthunder1
    :return:
    """
    url = ''.join([base_url, "/vrrp-a/vrid"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    floating_ip = [ip for ip in vThunder1_sec_ips if ip.split(".")[2] == "3"][0]
    vrid_list = SLB_param_data['parameters']['vrid-list']
    vrid_list[0]["floating-ip"] = {"ip-address-cfg": [{"ip-address": floating_ip}]}
    vrid_list[0]['blade-parameters']['priority'] = vrid_list[0]['blade-parameters']['priority'] - index
    data = {
        "vrid-list": vrid_list
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure vrrp rid")
            logger.error(response.text)
        else:
            logger.info('Configured vrrp rid')
            print('Configured vrrp rid')
    except Exception as exp:
        logger.error(exp)


def peer_group_config(base_url, authorization_token, vThunder_pvt_ips):
    """
    This function will configure peer group.
    AXAPI: /vrrp-a/peer-group
    :param authorization_token: authorization token
    :param  vThunder_pvt_ips: private ip list of vThunders data interface1
    :return:
    """
    url = ''.join([base_url, "/vrrp-a/peer-group"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    data = {
        "peer-group": {
            "peer": {
                "ip-peer-address-cfg": [
                    {
                        "ip-peer-address": vThunder_pvt_ips[0]
                    },
                    {
                        "ip-peer-address": vThunder_pvt_ips[1]
                    }
                ]
            }
        }
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code != 200:
            logger.error("Failed to configure peer group")
            logger.error(response.text)
        else:
            logger.info('Configured peer group')
            print('Configured peer group')
    except Exception as exp:
        logger.error(exp)


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


def update_auto_scale_group():
    auto_scale_group_name = SLB_param_data['parameters']["stackDetails"]["value"][0][
                                "stackName"] + "-auto-scale-group"
    capacity = SLB_param_data['parameters']['desiredCapacity']
    client = boto3.client('autoscaling')
    response = client.update_auto_scaling_group(
        AutoScalingGroupName=auto_scale_group_name,
        DesiredCapacity=capacity
    )
    try:
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print('Updated desired capacity of autoscale group to %s' % capacity)
            logger.info('Updated desired capacity of autoscale group to %s' % capacity)
        else:
            logger.error('Failed to update desired capacity of autoscale group.')
            logger.error(response.text)
    except Exception as e:
        logger.error('Error in updating desired capacity of autoscale group : ', exc_info=True)


# ------------------------------- driver code ----------------------
if __name__ == "__main__":

    # Get user input to apply ssl configurations.
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

    # Get user input to apply ha configurations.
    question = 'Do you want to configure HA (yes/no)?'
    while True:
        user_input = input(question)
        if user_input.lower() == "yes":
            ha_configure = True
            break
        elif user_input.lower() == "no":
            ha_configure = False
            break
        else:
            print("Please select correct input.")
    print("--------------------------------------------------------------------------------------------------------------------")

    # Validate and load parameter file data
    SLB_param_data = validate_load_json(upload_ssl_cert)
    if SLB_param_data:
        stack_name = SLB_param_data["parameters"]["stackDetails"]["value"][0]["stackName"]
        mngmnt_interfaces_list = []
        count = 1
        # get FTP server details

        ftp_server_name = SLB_param_data["parameters"]["stackDetails"]["value"][0]["stackName"] + "-" + "FTP-server"
        ftp_server_ip, ftp_server_id = get_ftp_server(ftp_server_name)
        # get list of management interface name of both vThunder devices
        for i in SLB_param_data["parameters"]["stackDetails"]["value"]:
            mngmnt_interfaces_list.append(i["stackName"] + "-" + "inst" + str(count) + "-mgmt-nic1")
            mngmnt_interfaces_list.append(i["stackName"] + "-" + "inst" + str(count + 1) + "-mgmt-nic1")
        # get management interface id of vthunder
        mngmnt_interface_ids = get_interfaces_ids(mngmnt_interfaces_list)
        # get public Ip of vThunder Instances
        public_ip_list = get_vthunder_public_ip(mngmnt_interface_ids)
        # get port list and lambda function name
        lambda_function_name = stack_name + "-lambda-function"
        port_list = json.dumps(SLB_param_data["parameters"]["port-list"])
        # secret managet to store AWS credentials

        # update lambda environment variables
        aws_region, secret_manager = get_lambda_function(lambda_function_name)
        update_lambda_env_variables(secret_manager, lambda_function_name, mngmnt_interface_ids[0],
                                    mngmnt_interface_ids[1], port_list, aws_region, stack_name)
        # get private ips and secondary ips of vThunder
        vThunder_pvt_ips = []
        vThunder1_sec_ips = []
        password_change = True
        # secret manager to store vThunders password
        secret_manager_name = stack_name + "-secret-manager"
        for vth in public_ip_list:
            pvt_ips, sec_ips = get_pvt_ips(vth)
            vThunder_pvt_ips.append([ip for ip in pvt_ips if ip.split(".")[2] == "2"][0])
            if len(sec_ips) > 1:
                vThunder1_sec_ips.append(sec_ips)
        password_count = 0
        print("Primary conditions for password validation, user should provide the new password according to the "
              "given combination: \n \nMinimum length of 9 characters \nMinimum lowercase character should be 1 \n"
              "Minimum uppercase character should be 1 \nMinimum number should be 1 \nMinimum special character "
              "should be 1 \nShould not include repeated characters \nShould not include more than 3 keyboard "
              "consecutive characters.\n")
        for vth in range(len(public_ip_list)):
            username = "admin"
            base_url = "https://{0}/axapi/v3".format(public_ip_list[vth][0])
            # change password of vThunder
            change_password = CHANGE_PASSWORD.VThunderPasswordHandler("admin")
            while password_change:
                vThNewPassword1 = getpass.getpass(prompt="Enter vThunder's new password:")
                vThNewPassword2 = getpass.getpass(prompt="Confirm new password:")
                if vThNewPassword1 == vThNewPassword2:
                    for i in range(len(public_ip_list)):
                        status = change_password.changed_admin_password(public_ip_list[i][0], public_ip_list[i][1],
                                                                        vThNewPassword1)
                        if status:
                            password_count = password_count + 1
                        if password_count == 2:
                            print("Password changed successfully.")
                            password_change = False
                            update_secret(secret_manager_name, vThNewPassword1)
                else:
                    print("Password does not match.")
                    continue
            print(
                "--------------------------------------------------------------------------------------------------------------------")
            print("Configuring vThunder with instance id {0}".format(public_ip_list[vth][1]))
            authorization_token = get_auth_token(username, vThNewPassword1, base_url)
            if authorization_token:
                # upload aws access key to vThunder
                aws_accesskey_upload(base_url, authorization_token, ftp_server_ip)
                # SLB configuration
                # 1. Invoke configure_ethernet
                configure_ethernet(base_url, authorization_token)
                # configure empty service group
                configure_service_group(SLB_param_data, base_url, authorization_token)
                # 2. Invoke configure_virtual_server
                configure_virtual_server(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips[0])

                # SSL configuration
                if upload_ssl_cert:
                    ssl_upload(SLB_param_data, base_url, authorization_token)

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

                    # 3. Invoke configure_primary_dns
                    configure_primary_dns(SLB_param_data, base_url, authorization_token)

                    # 4. Invoke configure_glm
                    configure_glm(SLB_param_data, base_url, authorization_token)

                    # 5. Invoke glm_request_send
                    glm_request_send(base_url, authorization_token)

                # HA configuration
                if ha_configure:
                    # 1. Invoke ip_route_config
                    ip_route_config(SLB_param_data, base_url, authorization_token)

                    # 2. Invoke vrrp_a_config
                    vrrp_a_config(SLB_param_data, base_url, authorization_token, device_id=vth + 1)
                    # 3. Invoke terminal_timeout_config
                    terminal_timeout_config(SLB_param_data, base_url, authorization_token)
                    # 4. Invoke vrrp_a_rid_config
                    vrrp_a_rid_config(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips[0], index=1)
                    # 5. Invoke peer_group_config
                    peer_group_config(base_url, authorization_token, vThunder_pvt_ips)

                # Invoke write_memory
                write_memory(base_url, authorization_token)


            else:
                print("Fails to get authorization token.")
        # update capacity of auto-scale group
        update_auto_scale_group()
        # delete ftp server
        delete_ftp_server(ftp_server_id)