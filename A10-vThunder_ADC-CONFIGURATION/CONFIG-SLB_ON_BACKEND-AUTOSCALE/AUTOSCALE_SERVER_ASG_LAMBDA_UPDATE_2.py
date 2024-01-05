"""
--------SCRIPT TO UPDATE LAMBDA ENVIRONMENT VARIABLES--------
Functions:

"""

from logger import logger
import warnings
import json
import boto3

warnings.filterwarnings('ignore')


def validate_load_json():
    """
    This function will validate and load parameter file's contents.
    """
    try:
        parameter_file = open('AUTOSCALE_SERVER_PARAM.json')
        asg_param_data = json.load(parameter_file)
        if 'parameters' in asg_param_data:
            if 'lambdaFunction' not in asg_param_data['parameters']:
                print("Lambda Function name not provided.")
                return None
            if 'desiredCapacity' not in asg_param_data['parameters']:
                print("auto scale desired capacity is not provided.")
                return None
            if 'autoscaleGroupName' not in asg_param_data['parameters']:
                print("AutoScale Group name not provided.")
                return None
            if 'port-list' not in asg_param_data['parameters']:
                print("Port list is not provided.")
                return None
        else:
            print("No parameters provided in file.")
            return None
        return asg_param_data
    except Exception as ex:
        logger.error(ex)
        return None


def get_lambda_function(lambda_function_name):
    client = boto3.client('lambda')
    response = client.get_function(
        FunctionName=lambda_function_name,
    )
    aws_region = response["Configuration"]["Environment"]["Variables"]["Region"]
    aws_secret_manager = response["Configuration"]["Environment"]["Variables"]["AWSSecretManagerName"]
    vthunder_secret_manager = response["Configuration"]["Environment"]["Variables"]["vThunderSecretManagerName"]
    mgmt_ips = response["Configuration"]["Environment"]["Variables"]["vThunderMgmtIPs"]
    return aws_region, aws_secret_manager, vthunder_secret_manager, mgmt_ips


def update_lambda_env_variables(aws_secret_manager, vthunder_secret_manager,
                                function_name, mgmt_ips, port_list, aws_region):
    """
    Function update lambda environment variables
    :param secret_manager: name of the secret manager
    :param function_name: lambda function name
    :param mgmt_ips: list of mgmt ips
    :param port_list: port list
    :param aws_region: aws region
    :return:
    """
    client = boto3.client('lambda')
    response = client.update_function_configuration(
        FunctionName=function_name,
        Environment={
            'Variables': {
                'AWSSecretManagerName': aws_secret_manager,
                'vThunderSecretManagerName': vthunder_secret_manager,
                'Region': aws_region,
                'vThunderMgmtIPs': mgmt_ips,
                'PortList': port_list
            }
        }
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print('Added PortList in %s lambda environment variables' % function_name)
        logger.info('Added PortList in %s lambda environment variables' % function_name)


def update_auto_scale_group():
    auto_scale_group_name = asg_param_data['parameters']["autoscaleGroupName"]
    capacity = asg_param_data['parameters']['desiredCapacity']
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
    # Validate and load parameter file data
    asg_param_data = validate_load_json()
    if asg_param_data:
        # get port list and lambda function name
        lambda_function_name = asg_param_data['parameters']["lambdaFunction"]
        port_list = json.dumps(asg_param_data["parameters"]["port-list"])
        # secret managet to store AWS credentials
        aws_region, aws_secret_manager, vthunder_secret_manager, mgmt_ips = get_lambda_function(lambda_function_name)
        # update lambda environment variables
        update_lambda_env_variables(aws_secret_manager=aws_secret_manager,
                                    vthunder_secret_manager=vthunder_secret_manager,
                                    function_name=lambda_function_name,
                                    port_list=port_list,
                                    aws_region=aws_region,
                                    mgmt_ips=mgmt_ips)

        # update capacity of auto-scale group
        update_auto_scale_group()
