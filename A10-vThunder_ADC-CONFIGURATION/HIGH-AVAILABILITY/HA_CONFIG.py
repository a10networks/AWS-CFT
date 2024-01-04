"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A SLB, SSL,GLM, HA --------
Functions:
    [a] Function to configure HA
    1. ip_route_config
    2. vrrp_a_config
    3. terminal_timeout_config
    4. vrrp_a_rid_config
    5. peer_group_config

    [b] Function to save configuration to memory
    1. write_memory
"""
import os.path
from logger import logger
import warnings
import json
import requests
import boto3
import base64
import getpass

warnings.filterwarnings('ignore')


def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('HA_CONFIG_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'publicIpList' not in SLB_data['parameters']:
                print("public ip is not provided.")
                return None
            if 'instanceIdList' not in SLB_data['parameters']:
                print("instance id is not provided.")
                return None
            if 'dns' not in SLB_data['parameters']:
                print("dns details not provided.")
                return None
        else:
            print("No parameters provided in file.")
            return None
        return SLB_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_pvt_ips(instance_id):
    """
        Function to get instance id.
        :param instance_id: instance id of thunders
        :return: pvt_ips, sec_pvt_ips
        """
    response = boto3.client('ec2').describe_instances(
        InstanceIds=[
            instance_id,
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
            print("Successfully uploaded AWS access key to vThunder.")
    except Exception as e:
        logger.error('Error in uploading AWS access key: ', exc_info=True)


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
        if response.status_code == 200:
            print('Successfully configured Primary DNS.')
            logger.info('Successfully configured Primary DNS.')

        else:
            logger.error('Failed to configure primary dns')
            logger.error(response.text)

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

        if response.status_code == 200:
            logger.info('Successfully configured IP Route.')
            print('Successfully configured IP Route.')

        else:
            logger.error('Failed to configure IP Route')
            logger.error(response.text)

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
        if response.status_code == 200:
            logger.info('Successfully configured Vrrp A common')
            print('Successfully configured Vrrp-A Common.')

        else:
            logger.error('Failed to configure Vrrp A common')
            logger.error(response.text)

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
        if response.status_code == 200:
            logger.info('Successfully configured Idle timeout')
            print('Successfully configured Idle Timeout.')

        else:
            logger.error('Failed to configure idle timeout')
            logger.error(response.text)

    except Exception as e:
        logger.error('Error in idle timeout configuration: ', exc_info=True)


def vrrp_a_rid_config(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips, index):
    """
    This function will configure vrrp rid.
    AXAPI: /vrrp-a/vrid
    :param SLB_param_data: parameters loaded from parameter file.
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
        if response.status_code == 200:
            logger.info('Configured vrrp rid')
            print('Successfully configured Vrrp Rid.')

        else:
            logger.error("Failed to configure vrrp rid")
            logger.error(response.text)
    except Exception as exp:
        logger.error('Error in idle timeout configuration: ', exc_info=True)


def peer_group_config(base_url, authorization_token, vThunder_pvt_ips):
    """
    This function will configure peer group.
    AXAPI: /vrrp-a/peer-group
    :param base_url: vthunder base url to access axapi
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
        if response.status_code == 200:
            logger.info('Successfully configured peer group')
            print('Successfully configured Peer Group.')
        else:
            logger.error("Failed to configure peer group")
            logger.error(response.text)
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
    SLB_param_data = validate_load_json()
    if SLB_param_data:
        count = 1
        # get FTP server details
        ftp_server_name = SLB_param_data["parameters"]["ftpServerName"]
        ftp_server_ip, ftp_server_id = get_ftp_server(ftp_server_name)
        public_ip = SLB_param_data["parameters"]["publicIpList"]
        public_ip_list = []
        for i in public_ip:
            j = i.replace(' ', '')
            public_ip_list.append(j)
        # get instance Id of vThunder Instances
        instance_id = SLB_param_data["parameters"]["instanceIdList"]
        instance_id_list = []
        for i in instance_id:
            j = i.replace(' ', '')
            instance_id_list.append(j)
        vThunder_pvt_ips = []
        vThunder1_sec_ips = []
        for vth in instance_id_list:
            pvt_ips, sec_ips = get_pvt_ips(vth)
            vThunder_pvt_ips.append([ip for ip in pvt_ips if ip.split(".")[2] == "2"][0])
            if len(sec_ips) > 1:
                vThunder1_sec_ips.append(sec_ips)
        for vth in range(len(public_ip_list)):
            username = "admin"
            base_url = "https://" + public_ip_list[vth] + "/axapi/v3"
            print("Configuring vThunder with ip " + public_ip_list[vth])
            vThNewPassword1 = getpass.getpass(prompt="Enter vThunder password:")
            authorization_token = get_auth_token(username, vThNewPassword1, base_url)
            if authorization_token:
                # upload aws access key to vThunder
                aws_accesskey_upload(base_url, authorization_token, ftp_server_ip)
                # HA configuration
                # 1. Configure primary dns
                configure_primary_dns(SLB_param_data, base_url, authorization_token)
                # 2. Invoke ip_route_config
                ip_route_config(SLB_param_data, base_url, authorization_token)
                # 3. Invoke vrrp_a_config
                vrrp_a_config(SLB_param_data, base_url, authorization_token, device_id=vth + 1)
                # 4. Invoke terminal_timeout_config
                terminal_timeout_config(SLB_param_data, base_url, authorization_token)
                # 5. Invoke vrrp_a_rid_config
                vrrp_a_rid_config(SLB_param_data, base_url, authorization_token, vThunder1_sec_ips[0], index=1)
                # 6. Invoke peer_group_config
                peer_group_config(base_url, authorization_token, vThunder_pvt_ips)
                # 7. Invoke write_memory
                write_memory(base_url, authorization_token)
                # 8. Logout from current session
                vth_logout(base_url, authorization_token)
                print(
                    "--------------------------------------------------------------------------------------------------------------------")
            else:
                print("Fails to get authorization token.")