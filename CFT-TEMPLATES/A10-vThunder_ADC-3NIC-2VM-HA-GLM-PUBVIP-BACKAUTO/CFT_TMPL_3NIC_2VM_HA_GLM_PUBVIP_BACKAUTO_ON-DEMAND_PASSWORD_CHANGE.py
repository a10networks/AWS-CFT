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


def validate_load_json():
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
            else:
                return SLB_param_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(
        SecretId=secret_name,
    )
    return response["SecretString"]


def update_secret(secret_name, vThNewPassword):
    """
    Function to update secret manager and store vThunder password
    :param secret_name: Secret Manager name
    :param vThNewPassword: vThunder password
    :return:
    """
    secret_string = {"vThPassword": vThNewPassword}
    client = boto3.client('secretsmanager')
    client.put_secret_value(
        SecretId=secret_name,
        SecretString=json.dumps(secret_string),
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


# ------------------------------- driver code ----------------------
if __name__ == "__main__":
    # load parameter file data
    SLB_param_data = validate_load_json()
    if SLB_param_data:
        stack_name = SLB_param_data["parameters"]["stackDetails"]["value"][0]["stackName"]
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
    password_change = True
    # secret manager to store vThunders password
    secret_manager_name = stack_name + "-secret-manager"

    count = 0
    print(
        "--------------------------------------------------------------------------------------------------------------------")
    while count < 3 and password_change:
        user_input = getpass.getpass(prompt="Enter vThunder's existing password:")
        old_password = get_secret(secret_manager_name)
        vTh_old_password = json.loads(old_password)["vThPassword"]
        if vTh_old_password == user_input:
            print("Primary conditions for password validation, user should provide the new password according to the "
                  "given combination: \n \nMinimum length of 9 characters \nMinimum lowercase character should be 1 \n"
                  "Minimum uppercase character should be 1 \nMinimum number should be 1 \nMinimum special character "
                  "should be 1 \nShould not include repeated characters \nShould not include more than 3 keyboard "
                  "consecutive characters.\n")
            change_password = CHANGE_PASSWORD.VThunderPasswordHandler("admin")
            while password_change:
                vThNewPassword1 = getpass.getpass(prompt="Enter vThunder's new password:")
                vThNewPassword2 = getpass.getpass(prompt="Confirm new password:")
                if vThNewPassword1 == vThNewPassword2:
                    password_count = 0
                    for i in range(len(public_ip_list)):
                        status = change_password.changed_admin_password(public_ip_list[i][0],
                                                                        vTh_old_password,
                                                                        vThNewPassword1)
                        if status:
                            password_count = password_count + 1
                        if password_count == 2:
                            print("Password changed successfully.")
                            print(
                                "--------------------------------------------------------------------------------------------------------------------")
                            password_change = False
                            update_secret(secret_manager_name, vThNewPassword1)
                else:
                    print("Password does not match.")
        else:
            count += 1
            print("Wrong existing password entered. Please try again.")
