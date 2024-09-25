"""
--------SCRIPT TO CONFIGURE THUNDER DEVICE AS A HA Across AZs --------
Functions:
    [a] Function to configure HA
    1. ip_route_config
    2. vrrp_a_config
    3. terminal_timeout_config
    4. vrrp_a_vrid_config
    5. peer_group_config

    [b] Function to configure Across HA
    1. ip_nat_pool_config
    2. cloud_services
    3. slb_virtual_server_config_update
    
    [c] Function to save configuration to memory
    1. write_memory
"""
from logger import logger
import warnings
import json
import requests
import boto3
import getpass
import sys

warnings.filterwarnings('ignore')

def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('HA_Across_AZs_CONFIG_PARAM.json')
        HA_data = json.load(parameter_file)
        if 'parameters' in HA_data:
            if 'instance_id_list' not in HA_data['parameters']:
                logger.error("Instance ID is not provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
                print("Instance ID is not provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
                return None
            if 'dns' not in HA_data['parameters']:
                logger.error("DNS is not provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
                print("DNS is not provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
                return None
        else:
            logger.error("No parameters have been provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
            print("No parameters have been provided in the parameter file 'HA_Across_AZs_CONFIG_PARAM.json'.")
            return None
        return HA_data
    except Exception as ex:
        logger.error("Failed to read the parameter file 'HA_Across_AZs_CONFIG_PARAM.json', error: %s" % ex)
        return None

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

def get_ips(instance_id):
    """
    Function to get public IP of the instance.
    :param instance_id: instance id of thunders
    :return: public_ip or None in case of error
    """
    try:
        response = boto3.client('ec2').describe_instances(
            InstanceIds=[instance_id],
        )
        public_ip = []
        for reservation in response['Reservations']:
            instances = reservation.get("Instances", [])
            if instances and "PublicIpAddress" in instances[0]:
                public_ip.append(instances[0]["PublicIpAddress"])
            else:
                return None
        return public_ip
    except Exception as exc:
        logger.error("An error occurred while finding the IP for instance ID %s, error: %s" % (instance_id,exc))
        return None
    
def get_auth_token(username, password, base_url):
    """
    Function to get authorization token.
    :param username: username for vthunder instance
    :param password: password of vthunder
    :param base_url: vthunder base URL to access axAPI
    :return: Authorization token
    axAPI: /axAPI/v3/auth
    """
    # axAPI header
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    # axAPI Auth URL json body
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
            logger.error('Failed to get authorization token from axAPI')
            print('Failed to get authorization token from axAPI')
    except Exception as e:
        logger.error('Error in authentication token: ', e)

def get_interface_ip(authorization_token,base_url):
    """
    Function to get interface IPs.
    :param authorization_token: base_url
    :param base_url: vthunder base URL to access axAPI
    :return: data-in_interface_ip, data-out_interface_ip
    axAPI: /interface/brief/oper
    """
    # axAPI header
    headers = {
        "Authorization": f"A10 {authorization_token}",
        "Content-Type": "application/json"
    }
    url = f"{base_url}/interface/brief/oper"

    try:
        with requests.Session() as session:
            response = session.get(url, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json()
            # Extract IP addresses
            datain_interface_ip = next((interface['ipv4_addr'] for interface in data['brief']['oper']['interfaces'] if interface['port_num'] == '1'), None)
            dataout_interface_ip = next((interface['ipv4_addr'] for interface in data['brief']['oper']['interfaces'] if interface['port_num'] == '2'), None)
            return datain_interface_ip, dataout_interface_ip
    except requests.exceptions.RequestException as e:
        print('Error in fetching interface IP address:', e)
        return None

def aws_accesskey_upload(base_url, authorization_token, ftp_server_ip):
    """
    Function to configure AWS Access keys to vThunder
    :param base_url: base URL of axAPI
    :param authorization_token: authorization_token
    :param ftp_server_ip: public ip of ftp server
    :return:
    axAPI:/admin/admin/aws-accesskey
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
        if response.status_code == 200:
            print('Successfully uploaded AWS access key to vThunder.')
            logger.info('Successfully uploaded AWS access key to vThunder.')

        else:
            logger.error('Failed to upload AWS access key.')
            logger.error(response.text)
    except Exception as e:
        logger.error('Error in uploading AWS access key: ', e)

def vth_logout(base_url, authorization_token):
    """
     function to logout vthunder session
    :param base_url: vthunder base URL to access axAPI
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

def configure_primary_dns(HA_param_data, base_url, authorization_token):
    """
    This function will configure Primary DNS
    :param base_url: vthunder base URL to access axAPI
    :param authorization_token: Authorization token
    :return:
    axAPI:/ip/dns/primary
    """
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    dns = HA_param_data["parameters"]["dns"]["value"]
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
        logger.error('Error in configuring primary dns : ', e)

def ip_route_config(HA_param_data, base_url, authorization_token,index):
    """
    This function will configure the IP route.
    axAPI: /ip/route/rib
     :param HA_param_data: parameters loaded from parameter file.
     :param base_url: vthunder base URL to access axAPI
    :param authorization_token: authorization token
    :return:
    """
    url = ''.join([base_url, "/ip/route/rib"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    if index == 0:
        rib_list = HA_param_data['parameters']['rib_list_active']
    else:
        rib_list = HA_param_data['parameters']['rib_list_standby']
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
        logger.error('Error in configuring IP Route : ', e)

def vrrp_a_config(HA_param_data, base_url, authorization_token, device_id):
    """
    This function will configure the Vrrp-A common.
    :param HA_param_data: parameters loaded from parameter file.
    axAPI: /vrrp-a/common
    :param base_url: vthunder base URL to access axAPI
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
    set_id = HA_param_data['parameters']['vrrp_a']['set-id']
    data = {
        "common": {"device-id": device_id,
                   "set-id": set_id,
                   "action": "enable"
                   }
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            logger.info('Successfully configured Vrrp-A common')
            print('Successfully configured Vrrp-A Common.')

        else:
            logger.error('Failed to configure Vrrp-A common')
            logger.error(response.text)

    except Exception as e:
        logger.error('Error in Vrrp-A common configuration : ', e)

def terminal_timeout_config(HA_param_data, base_url, authorization_token):
    """
        This function will configure Idle Timeout.
        axAPI: /terminal
        :param HA_param_data: parameters loaded from parameter file.
        :param base_url: vthunder base URL to access axAPI
        :param authorization_token: authorization token
        :return:
        """
    url = ''.join([base_url, "/terminal"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    timeout = HA_param_data['parameters']['terminal']['idle-timeout']
    data = {
        "terminal": {"idle-timeout": timeout}
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            logger.info('Successfully configured Idle Timeout')
            print('Successfully configured Idle Timeout.')

        else:
            logger.error('Failed to configure Idle Timeout')
            logger.error(response.text)

    except Exception as e:
        logger.error('Error in Idle Timeout configuration: ', e)

def vrrp_a_vrid_config(HA_param_data, base_url, authorization_token, index):
    """
        This function will configure VRRP-A vrid.
        axAPI: /vrrp-a/vrid
        :param HA_param_data: parameters loaded from parameter file.
        :param base_url: vthunder base URL to access axAPI
        :param authorization_token: authorization token
        :param index: index to identify active and standby
        :return:
        """
    
    url = ''.join([base_url, "/vrrp-a/vrid"])
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    if index == 0:
        vrid_list = HA_param_data['parameters']['vrid_list_active_thunder']
    else:
        vrid_list = HA_param_data['parameters']['vrid_list_standby_thunder']
    data = {
        "vrid-list": vrid_list
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            logger.info('Successfully configured VRRP-A Vrid')
            print('Successfully configured VRRP-A Vrid.')

        else:
            logger.error("Failed to configure VRRP-A Vrid")
            logger.error(response.text)
    except Exception as e:
        logger.error('Error in VRRP-A Vrid configuration: ', e)

def peer_group_config(base_url, authorization_token, vThunder_pvt_ips):
    """
    This function will configure Peer Group.
    axAPI: /vrrp-a/peer-group
    :param base_url: vthunder base URL to access axAPI
    :param authorization_token: authorization token
    :param  vThunder_pvt_ips: private IP list of vThunders data-in interface
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
            logger.info('Successfully configured Peer Group')
            print('Successfully configured Peer Group.')
        else:
            logger.error("Failed to configure Peer Group")
            logger.error(response.text)
    except Exception as e:
        logger.error('Error in Peer Group configuration: ', e)

def write_memory(base_url, authorization_token):
    """
    Function to save configurations on active partition
    :param base_url: base URL of axAPI
    :param authorization_token: authorization token
    :return:
    axAPI: /axAPI/v3/active-partition
    axAPI: /axAPI/v3//write/memory
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
            logger.error('Error in writing to memory : ', e)

# -------------------------------Across HA Configuration ----------------------
def ip_nat_pool_config(HA_param_data,base_url, authorization_token, index):
    """
        This function will configure IP NAT pool.
        axAPI: /ip/nat/pool
        :param HA_param_data: parameters loaded from parameter file.
        :param base_url: vthunder base URL to access axAPI
        :param authorization_token: authorization token
        :param index: index to identify active and standby
        :return:
        """
    headers = {
        "Authorization": f"A10 {authorization_token}",
        "Content-Type": "application/json"
    }
    url = f"{base_url}/ip/nat/pool"
    if index == 0:
        pool_list = HA_param_data["parameters"]["pool_list_active_thunder"]
    elif index == 1:
        pool_list = HA_param_data["parameters"]["pool_list_standby_thunder"]
    data = {"pool-list":pool_list}
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if response.status_code == 200:
            logger.info('Successfully configured IP NAT pool')
            print('Successfully configured IP NAT pool.')
        else:
            logger.error("Failed configured IP NAT pool")
            logger.error(response.text)
    except requests.exceptions.RequestException as e:
        logger.error('Error in IP NAT pool configuration: ', e)

def cloud_services(HA_param_data, base_url, authorization_token,index):
    """
    This function will configure Cloud Services
    :param HA_param_data: parameters loaded from parameter file.
    :param base_url: vthunder base URL to access axAPI
    :param authorization_token: Authorization token
    :param index: index to identify active and standby
    :return:
    axAPI:/cloud-services/cloud-provider/aws/multi-az-failover/vrid
    """
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    if index == 0:
        data= HA_param_data["parameters"]["cloud_services_cloud_provider_active_thunder"]
    else:
        data= HA_param_data["parameters"]["cloud_services_cloud_provider_standby_thunder"]
    multi_az_failover_vrid = data["multi-az-failover"]["vrid"]
    vrid_data = {"vrid": {
        "vrid-number": 0,
        "vip-list": [
            {
                "vip-number": 0,
                "private-ip": multi_az_failover_vrid["vip-list"][0].get("private-ip",""),
            }
        ]
    }}
    if "elastic-ip" in multi_az_failover_vrid["vip-list"][0] and multi_az_failover_vrid["vip-list"][0]["elastic-ip"]:
        vrid_data["vrid"]["vip-list"][0]["elastic-ip"] = multi_az_failover_vrid["vip-list"][0]["elastic-ip"]

    optional_fields = ["route-table-id", "vip-interface-id", "fip-interface-id", "vip-dest", "fip-dest"]
    for field in optional_fields:
        if field in multi_az_failover_vrid and multi_az_failover_vrid[field]:
            vrid_data["vrid"][field] = multi_az_failover_vrid[field]
    urlcloudservices = "".join([base_url, "/cloud-services/cloud-provider/aws/multi-az-failover/vrid"])
    try:
        response = requests.post(urlcloudservices, headers=headers, data=json.dumps(vrid_data), verify=False)
        if response.status_code == 200:
            print('Successfully configured Cloud Services.')
            logger.info('Successfully configured Cloud Services.')

        else:
            logger.error('Failed to configure Cloud Services')
            logger.error(response.text)

    except Exception as e:
        logger.error('Error in configuring Cloud Services : ', e)

def slb_virtual_server_config_update(HA_param_data,base_url, authorization_token, index):
    """
    This function will update slb virtual server
    :param HA_param_data: parameters loaded from parameter file.
    :param base_url: vthunder base URL to access axAPI
    :param authorization_token: Authorization token
    :param index: index to identify active and standby
    :return:
    axAPI:/slb/virtual-server/${server_name}/port/${port-number}+${protocol}
    """
    headers = {
        "accept": "application/json",
        "Authorization": "".join(["A10 ", authorization_token]),
        "Content-Type": "application/json"
    }
    if index == 0:
        virtual_server = HA_param_data["parameters"]["slb_virtual_server_active_thunder"]
    elif index == 1:
        virtual_server = HA_param_data["parameters"]["slb_virtual_server_standby_thunder"]
    
    for server in virtual_server:
        for port in server["port-list"]:
            update_url = f"{base_url}/slb/virtual-server/{server['name']}/port/{port['port-number']}+{port['protocol']}"
            data = {
                "port":{
                    "ha-conn-mirror": port.get('ha-conn-mirror'), 
                    "pool": port.get('pool')
                }
            }
            try:
                get_response = requests.get(update_url, headers=headers, verify=False)
                get_response.raise_for_status()
                current_data = get_response.json()
                
                current_data['port']['ha-conn-mirror'] = port.get('ha-conn-mirror', current_data['port'].get('ha-conn-mirror'))
                current_data['port']['pool'] = port.get('pool', current_data['port'].get('pool'))

                response = requests.put(update_url, headers=headers, data=json.dumps(current_data), verify=False)

                if response.status_code == 200:
                    logger.info('Successfully updated SLB Virtual Server %s configuration' % server["name"])
                    print('Successfully updated SLB Virtual Server %s configuration.' % server["name"])
                else:
                    logger.error('Failed to update SLB Virtual Server %s configuration' % server["name"])
                    logger.error(response.text)
            except Exception as e:
                logger.error('Error in updating the SLB Virtual Server %s configuration: %s' % (server["name"], e))
                print('Error in updating the SLB Virtual Server %s configuration: %s' % (server["name"], e))
    

# ------------------------------- driver code ----------------------
if __name__ == "__main__":
    # Validate and load parameter file data
    HA_param_data = validate_load_json()
    if HA_param_data:
        count = 1
        # get FTP server details
        ftp_server_name = HA_param_data["parameters"]["ftp_server_name"]
        ftp_server_ip, ftp_server_id = get_ftp_server(ftp_server_name)
        # get instance Id of vThunder Instances
        instance_id = HA_param_data["parameters"]["instance_id_list"]
        instance_id_list = []
        for i in instance_id:
            j = i.replace(' ', '')
            instance_id_list.append(j)
        authorization_tokens = {}
        data_in_ips = {}
        data_out_ips = {}
        
        for vth_id in instance_id_list:
            public_ip = get_ips(vth_id)
            if public_ip is None:
                logger.error("Failed to find the public IP associated with instance ID: %s." % vth_id)
                sys.exit()
            username = "admin"
            base_url = "https://" + public_ip[0] + "/axapi/v3"
            print("Authorization for vThunder with IP " + public_ip[0])
            vThNewPassword = getpass.getpass(prompt="Enter vThunder password:")
            # Get authorization token and interface IP
            authorization_token = get_auth_token(username, vThNewPassword, base_url)
            if authorization_token:
                data_in_ip,data_out_ip = get_interface_ip(authorization_token, base_url)
                
                # Store the authorization token and data in IP in their respective dictionaries
                authorization_tokens[public_ip[0]] = authorization_token
                data_in_ips[public_ip[0]] = data_in_ip
                data_out_ips[public_ip[0]] = data_out_ip
            else:
                logger.error("Failed to get authorization token for vThunder IP: %s" % public_ip[0])
                print("Failed to get authorization token for vThunder IP: %s" % public_ip[0])
                sys.exit()
        
        for index, (public_ip, token) in enumerate(authorization_tokens.items()):
            base_url = "https://" + public_ip + "/axapi/v3"
            print(
                    "--------------------------------------------------------------------------------------------------------------------")
            print("Configuring vThunder with IP " + public_ip)
            logger.info("Configuring vThunder with IP " + public_ip)
            if token:
                print("Please note that we support generation of credential through IAM Role attached to instance from ACOS 6.0.5 onward.")
                checkIAMRole = input("Does the instance have IAM role attached or not (YES/NO)? ")
                if checkIAMRole.lower() == "yes":
                    logger.info("No need to import the AWS access key and secret key. A file containing both the key will be generate using the IAM role attached to instance.")
                elif checkIAMRole.lower() == "no":
                    # upload aws access key to vThunder
                    aws_accesskey_upload(base_url, token, ftp_server_ip)
                else:
                    print("Invalid value. Expected 'YES' or 'NO'.")
                # HA configuration
                # 1. Configure primary dns
                configure_primary_dns(HA_param_data, base_url, token)
                # 2. Invoke ip_route_config
                ip_route_config(HA_param_data, base_url, token,index)
                 # 3. Invoke vrrp_a_config
                vrrp_a_config(HA_param_data, base_url, token, device_id=index + 1)
                # 4. Invoke terminal_timeout_config
                terminal_timeout_config(HA_param_data, base_url, token)
                # 5. Invoke vrrp_a_vrid_config
                vrrp_a_vrid_config(HA_param_data, base_url, token, index)
                # 6. Invoke peer_group_config
                peer_group_config(base_url, token, list(data_in_ips.values()))
                # 7. Invoke ip_nat_pool config
                ip_nat_pool_config(HA_param_data,base_url,token,index)
                # 8. Invoke cloud-services cloud-provider config
                cloud_services(HA_param_data,base_url,token,index)
                # 9. Set the source-nat auto and ha-conn-mirror
                slb_virtual_server_config_update(HA_param_data,base_url,token,index)
                # 10. Invoke write_memory
                write_memory(base_url, token)
                # 11. Logout from current session
                vth_logout(base_url, token)
                print(
                    "--------------------------------------------------------------------------------------------------------------------")
        
    else:
        print("Invalid HA parameters provided; configuration not applied.")
        sys.exit()