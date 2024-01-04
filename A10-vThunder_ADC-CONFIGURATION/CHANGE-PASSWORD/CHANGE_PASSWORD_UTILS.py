"""
--------SCRIPT TO CHANGE V-THUNDER's ADMIN PASSWORD --------
"""
from logger import logger
import warnings
import json
import requests

warnings.filterwarnings('ignore')


class VThunderPasswordHandler:
    def __init__(self, vThUsername):
        self.public_ip = None
        self.vThUsername = vThUsername

    def get_auth_token(self, password):
        """
        Function to get authorization token.
        :param password: password of vthunder
        # :param public_ip: vthunder public ip
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
            "username": self.vThUsername,
            "password": password
        }
        }
        base_url = "https://{0}/axapi/v3".format(self.public_ip)
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

    def write_memory(self, authorization_token):
        """
        Function to save configurations on active partition
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
        base_url = "https://{0}/axapi/v3".format(self.public_ip)
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
                    logger.info("Password change configurations saved on partition: " + partition)
            except Exception as e:
                logger.error('Error in writing to memory : ', exc_info=True)

    def changed_admin_password(self, vthunder_ip, vThOldPassword, vThNewPassword):
        """
        Function for changing admin password
        AXAPI: /admin/{admin-user}/password
        :param vthunder_ip: public ip of vThunder
        :param vThOldPassword: vThunde's Old Password
        :param vThNewPassword: vThunder's New password
        """
        self.public_ip = vthunder_ip
        base_url = "https://{0}/axapi/v3".format(self.public_ip)
        auth_token = self.get_auth_token(vThOldPassword)
        url = ''.join([base_url, "/admin/admin/password"])
        headers = {
            "accept": "application/json",
            "Authorization": "".join(["A10 ", auth_token]),
            "Content-Type": "application/json"
        }
        data = {
            "password": {
                "password-in-module": vThNewPassword,
                "encrypted-in-module": "Unknown Type: encrypted"
            }
        }
        try:
            response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
            if response.status_code != 200:
                logger.error("Failed to change password")
                logger.error(response.text)
                return False
            else:
                auth_token = self.get_auth_token(vThNewPassword)
                self.write_memory(auth_token)
                return True
        except Exception as exp:
            logger.error(exp)
