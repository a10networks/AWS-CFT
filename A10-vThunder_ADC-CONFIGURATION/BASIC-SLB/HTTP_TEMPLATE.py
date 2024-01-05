"""
--------SCRIPT TO CONFIGURE HTTP TEMPLATE ON VTHUNDER--------
"""

from logger import logger
import warnings
import json
import requests


warnings.filterwarnings('ignore')


class VThunderHttpTemplateHandler:
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
            if response.status_code == 200:
                authorization_token = json.loads(response.text)["authresponse"]["signature"]
                return authorization_token
            else:
                logger.error('Failed to get authorization token from AXAPI')
                logger.error(response.text)

        except Exception as e:
            logger.error('Error in authentication token: ', exc_info=True)

    def vth_logout(self, vthunder_ip, authorization_token):
        """
        logout vthunder session
        :return 200
        """
        self.public_ip = vthunder_ip
        base_url = "https://{0}/axapi/v3".format(self.public_ip)
        url = f"{base_url}/logoff"
        payload = {}

        headers = {
            "Authorization": "".join(["A10 ", authorization_token]),
            "Content-Type": "application/json"
        }

        try:
            response = requests.request("GET", url, headers=headers, data=payload, verify=False)
            if response.status_code == 200:
                return True

            else:
                logger.error('Failed to logout vThunder')
                logger.error(response.text)
                return False
        except Exception as e:
            logger.error(e)
            return False

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

    def configure_http_template(self, vthunder_ip, http_list, vth_password):
        """
        Function to configure http template
        :param vthunder_ip:vthunder public ip address
        :param vth_password: vthunder password
        :param http_list: body of http template
        :return:
        AXAPI: /axapi/v3/slb/template/http
        """
        self.public_ip = vthunder_ip
        auth_token = self.get_auth_token(vth_password)
        headers = {
            "Authorization": "".join(["A10 ", auth_token]),
            "accept": "application/json",
            "Content-Type": "application/json"
        }

        base_url = "https://{0}/axapi/v3".format(self.public_ip)
        url = "".join([base_url, "/slb/template/http"])

        data = {
            "http-list":http_list
        }
        try:
            response = requests.post(url, headers=headers,
                                     data=json.dumps(data), verify=False)

            if response.status_code == 200:
                logger.info("Successfully configured http template.")
                self.vth_logout(vthunder_ip, auth_token)
                return True
            else:
                logger.error("Failed to configure http template.")
                logger.error(response.text)
                return False


        except Exception as e:
            logger.error('Error in configuring virtual servers: ', exc_info=True)

