"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SLB, SSL, HA --------
Functions:
    [a] Function for SLB Configuration on vthunder
    1. get_auth_token
    2. configure_ethernet
    3. configure_server
    4. configure_service_group
    5. configure_virtual_server

    [b] Function for SSL Configuration on vthunder
    1. ssl_upload

    [c] Function to configure HA
    1. ip_route_config
    2. vrrp_a_config
    3. terminal_timeout_config
    4. vrrp_a_rid_config
    5. peer_group_config

    [d] Function to save configuration to memory
    1. write_memory
"""
import os.path
from logger import logger
import warnings
import json
import requests
import boto3

warnings.filterwarnings('ignore')


def validate_load_json(ssl_status):
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('CFT_TMPL_3NIC_2VM_HA_CONFIG_SLB_SSL_HA_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'stackDetails' not in SLB_data['parameters']:
                print("stack name is not provided.")
                return None
            if 'server-list' not in SLB_data['parameters']:
                print("server list is not provided.")
                return None
            if 'serviceGroupList' not in SLB_data['parameters']:
                print("service group list is not provided.")
                return None
            if 'virtualServerList' not in SLB_data['parameters']:
                print("virtual server list is not provided.")
                return None
            if 'dns' not in SLB_data['parameters']:
                print("dns details not provided.")
                return None
            if ssl_status:
                if 'sslConfig' in SLB_data['parameters']:
                    if 'requestTimeOut' not in SLB_data['parameters']['sslConfig']:
                        print("request timeout details not provided.")
                        return None
                    if 'Path' not in SLB_data['parameters']['sslConfig']:
                        print("ssl certificate file path not provided.")
                        return None
                    if 'File' not in SLB_data['parameters']['sslConfig']:
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
            print('Failed to get authorization token from AXAPI')
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
                print("Failed to configure ethernet ip")
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
                print("Failed to configure server " + server_name)
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
            print("Failed to configure service group")
        else:
            logger.info("Configured service group")
            print("Configure service group")
    except Exception as e:
        logger.error('Error in configuring service group: ', exc_info=True)


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
        if response.status_code != 204:
            logger.error("Failed to configure SSL certificate")
            print("Failed to configure SSL certificate")
        else:
            logger.info("SSL Configured.")
            print("SSL Configured.")
    except Exception as e:
        logger.error('Error in configuring SSL : ', exc_info=True)


# ------------------------------- HA Configuration ----------------------
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


def ip_route_config(SLB_param_data, base_url, authorization_token):
    """
    This function will configure the IP route.
    AXAPI: /ip/route/rib
     :param SLB_param_data: parameters loaded from parameter file.
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
            logger.error('Failed to configure IP Route')
            logger.error(response.text)
        else:
            logger.info('Configured IP Route')
            print('Configured IP Route')
    except Exception as e:
        logger.error('Error in configuring IP Route : ', exc_info=True)


def vrrp_a_config(SLB_param_data, base_url, authorization_token, device_id):
    """
    This function will configure the vrrp.
    :param SLB_param_data: parameters loaded from parameter file.
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
            logger.error('Failed to configure Vrrp A common')
            logger.error(response.text)
        else:
            logger.info('Configured Vrrp A common')
            print('Configured Vrrp A common')
    except Exception as e:
        logger.error('Error in Vrrp A common configuration : ', exc_info=True)


def terminal_timeout_config(SLB_param_data, base_url, authorization_token):
    """
        This function will configure terminal timeout.
        AXAPI: /terminal
        :param SLB_param_data: parameters loaded from parameter file.
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
            logger.error('Failed to configure idle timeout')
            logger.error(response.text)
        else:
            logger.info('Configured idle timeout')
            print('Configured idle timeout')
    except Exception as e:
        logger.error('Error in idle timeout configuration: ', exc_info=True)


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
        logger.error('Error in idle timeout configuration: ', exc_info=True)


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
        logger.error('Error in idle timeout configuration: ', exc_info=True)


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
                print("Failed to run write memory command")
            else:
                logger.info("Configurations are saved on partition: " + partition)
                print("Configurations are saved on partition: " + partition)
        except Exception as e:
            logger.error('Error in writing to memory : ', exc_info=True)


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

    # Validate and load parameter file data
    SLB_param_data = validate_load_json(upload_ssl_cert)
    if SLB_param_data:
        # get slb server's private IP
        server_name = SLB_param_data["parameters"]["stackDetails"]["value"][0]["stackName"] + "-" + "server"
        server_pvt_ip = get_server_pvt_ip(server_name)
        mngmnt_interfaces_list = []
        count = 1
        # get list of management interface name of both vThunder devices
        for i in SLB_param_data["parameters"]["stackDetails"]["value"]:
            mngmnt_interfaces_list.append(i["stackName"] + "-" + "inst" + str(count) + "-mgmt-nic1")
            mngmnt_interfaces_list.append(i["stackName"] + "-" + "inst" + str(count + 1) + "-mgmt-nic1")
        # get management interface id of vthunder
        mngmnt_interface_ids = get_interfaces_ids(mngmnt_interfaces_list)
        # get public Ip of vThunder Instances
        public_ip_list = get_vthunder_public_ip(mngmnt_interface_ids)
        # get private ips and secondary ips of vThunder
        vThunder_pvt_ips = []
        vThunder1_sec_ips = []
        for vth in public_ip_list:
            pvt_ips, sec_ips = get_pvt_ips(vth)
            vThunder_pvt_ips.append([ip for ip in pvt_ips if ip.split(".")[2] == "2"][0])
            if len(sec_ips) > 1:
                vThunder1_sec_ips.append(sec_ips)
        for vth in range(len(public_ip_list)):
            print("Configuring vThunder with instance id {0}".format(public_ip_list[vth][1]))
            username = "admin"
            base_url = "https://{0}/axapi/v3".format(public_ip_list[vth][0])
            authorization_token = get_auth_token(username, public_ip_list[vth][1], base_url)
            if authorization_token:
                # SLB configuration
                # 1. Invoke configure_ethernet
                configure_ethernet(base_url, authorization_token)
                # 2. Configure slb server
                configure_server(SLB_param_data, base_url, authorization_token, server_pvt_ip, server_name)
                # 3. configure service group
                configure_service_group(SLB_param_data, base_url, authorization_token, server_name)
                # 4. Invoke configure_virtual_server
                configure_virtual_server(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips[0])
                # SSL configuration
                if upload_ssl_cert:
                    ssl_upload(SLB_param_data, base_url, authorization_token)

                # HA configuration
                if ha_configure:
                    # 5. Configure primary dns
                    configure_primary_dns(SLB_param_data, base_url, authorization_token)
                    # 6. Invoke ip_route_config
                    ip_route_config(SLB_param_data, base_url, authorization_token)
                    # 7. Invoke vrrp_a_config
                    vrrp_a_config(SLB_param_data, base_url, authorization_token, device_id=vth + 1)
                    # 8. Invoke terminal_timeout_config
                    terminal_timeout_config(SLB_param_data, base_url, authorization_token)
                    # 9. Invoke vrrp_a_rid_config
                    vrrp_a_rid_config(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips[0], index=1)
                    # 10. Invoke peer_group_config
                    peer_group_config(base_url, authorization_token, vThunder_pvt_ips)

                # 11. Invoke write_memory
                write_memory(base_url, authorization_token)
            else:
                print("Fails to get authorization token.")
