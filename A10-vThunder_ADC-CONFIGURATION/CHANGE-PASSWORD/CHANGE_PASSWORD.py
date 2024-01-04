"""
--------SCRIPT TO CHANGE PASSWORD OF THUNDER DEVICE --------
Functions:
    [a] Function to change password of vthunder
    [b] Function to save configuration to memory
    1. write_memory
"""

from logger import logger
import warnings
import json
import requests
import boto3
import CHANGE_PASSWORD_UTILS
import getpass
import ipaddress

warnings.filterwarnings('ignore')


def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    :return:
    """
    try:
        parameter_file = open('CHANGE_PASSWORD_PARAM.json')
        SLB_data = json.load(parameter_file)
        if 'parameters' in SLB_data:
            if 'publicIpList' not in SLB_data['parameters']:
                print("public ip is not provided.")
                return None
            if 'secretManagerName' not in SLB_data['parameters']:
                print("secret manager name is not provided.")
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
        if response.status_code != 200:
            logger.error('Failed to get authorization token from AXAPI')
            print('Failed to get authorization token from AXAPI')
        else:
            authorization_token = json.loads(response.text)["authresponse"]["signature"]
            return authorization_token
    except Exception as e:
        logger.error('Error in authentication token: ', exc_info=True)
        return None


def update_secret(secret_name, updated_username, updated_password):
    """
    Function to update secret manager and store vThunder password
    :param secret_name: Secret Manager name
    :param updated_username: updated username of vThunder
    :param updated_password: updated password of vThunder
    :return:
    """
    secret_string = {"username": updated_username, "password": updated_password}
    client = boto3.client('secretsmanager')
    response = client.put_secret_value(
        SecretId=secret_name,
        SecretString=json.dumps(secret_string),
    )
    print("Succesfully updated password in Secret Manager.")


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
                logger.error("Failed to run write memory command.")
                print("Failed to run write memory command.")
            else:
                logger.info("Configurations are saved on partition: " + partition)
                print("Configurations are saved on partition: " + partition)
        except Exception as e:
            logger.error('Error in writing to memory : ', exc_info=True)


# ------------------------------- driver code ----------------------
if __name__ == "__main__":
    # Validate and load parameter file data
    SLB_param_data = validate_load_json()
    if SLB_param_data:
        count = 0
        # get public Ip of vThunder Instances
        public_ip = SLB_param_data["parameters"]["publicIpList"]
        if public_ip == []:
            while True:
                public_ip = input("Enter vThunder's host/IP address: ")

                try:
                    ip = ipaddress.IPv4Address(public_ip)
                    vthunders_old_password = list()
                    password_change = True
                    print(
                        "Primary conditions for password validation, user should provide the new password according to the "
                        "given combination: \n \nMinimum length of 9 characters \nMinimum lowercase character should be 1 \n"
                        "Minimum uppercase character should be 1 \nMinimum number should be 1 \nMinimum special character "
                        "should be 1 \nShould not include repeated characters \nShould not include more than 3 keyboard "
                        "consecutive characters.\n")
                    # get password of each vthunder
                    # for vth in range(len(public_ip)):
                    print("\nSpecify EC2 instance ID as a default password for vThunder EC2 instance.\n")
                    old_password = getpass.getpass(prompt="Enter vThunder [%s] "
                                                          "password:" % public_ip)
                    # get new password
                    password = 'admin'
                    confirm_password = 'confirm_admin'
                    while password != confirm_password:
                        password = getpass.getpass(prompt="Enter vThunder new password:")
                        confirm_password = getpass.getpass(prompt="Confirm new password:")
                        if password != confirm_password:
                            print("password and confirm password is not matching.")
                        # change password of vThunder
                        change_password = CHANGE_PASSWORD_UTILS.VThunderPasswordHandler('admin')
                        status = change_password.changed_admin_password(public_ip,
                                                                        old_password,
                                                                        password)
                        if status:
                            print("vThunder [%s] Password changed successfully." % public_ip)
                            base_url = "https://" + public_ip + "/axapi/v3"
                            authorization_token = get_auth_token(username='admin',
                                                                 password=password,
                                                                 base_url=base_url)
                            if authorization_token:
                                # 11. Invoke write_memory
                                write_memory(base_url, authorization_token)
                                exit()
                            else:
                                print("Fails to get authorization token.")
                        else:
                            print("Failed to change password of vThunder [%s]" % public_ip)
                except ipaddress.AddressValueError:
                    print("Invalid IP address. Please try again.")
        else:

            public_ip_list=[]
            for ip in public_ip:
                ip_new = ip.replace(' ', '')
                public_ip_list.append(ip_new)
            vthunders_old_password = list()
            password_change = True
            print("Primary conditions for password validation, user should provide the new password according to the "
                  "given combination: \n \nMinimum length of 9 characters \nMinimum lowercase character should be 1 \n"
                  "Minimum uppercase character should be 1 \nMinimum number should be 1 \nMinimum special character "
                  "should be 1 \nShould not include repeated characters \nShould not include more than 3 keyboard "
                  "consecutive characters.\n")

            # get password of each vthunder
            for vth in range(len(public_ip_list)):
                print("\nSpecify EC2 instance ID as a default password for vThunder EC2 instance.\n")
                old_password = getpass.getpass(prompt="Enter vThunder [%s] "
                                                      "password:" % public_ip_list[vth])
                vthunders_old_password.append(old_password)
                # get new password
                password = 'admin'
                confirm_password = 'confirm_admin'
                while password != confirm_password:
                    password = getpass.getpass(prompt="Enter vThunder new password:")
                    confirm_password = getpass.getpass(prompt="Confirm new password:")
                    if password != confirm_password:
                        print("password and confirm password is not matching.")
            # change password of vThunder
                change_password = CHANGE_PASSWORD_UTILS.VThunderPasswordHandler('admin')
                status = change_password.changed_admin_password(public_ip_list[vth],
                                                                old_password,
                                                                password)
                if status:
                    print("vThunder [%s] Password changed successfully." % public_ip_list[vth])
                    base_url = "https://" + public_ip_list[vth] + "/axapi/v3"
                    authorization_token = get_auth_token(username='admin',
                                                         password=password,
                                                         base_url=base_url)
                    if authorization_token:
                        # 11. Invoke write_memory
                        write_memory(base_url, authorization_token)
                    else:
                        print("Fails to get authorization token.")
                else:
                    print("Failed to change password of vThunder [%s]" % vth)
        # update vthunder secret manager credentials
        question = "Do you want to update password in Secret Manager? [yes/no]"
        while True:
            user_input = input(question)
            if user_input.strip().lower() == "yes":
                secret_manager_name = SLB_param_data["parameters"]["secretManagerName"]
                update_secret(secret_manager_name,
                              updated_username='admin',
                              updated_password=password)

                break
            elif user_input.lower() == "no":
                break
            else:
                print("Please select correct input.")