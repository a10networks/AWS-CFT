import logging
import os
import boto3
from botocore.exceptions import ClientError


def create_bucket(bucket_name):
    """Create an S3 bucket
    :param bucket_name: Bucket to create
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        s3_client = boto3.client('s3')
        s3_client.create_bucket(Bucket=bucket_name)

    except ClientError as e:
        logging.error(e)
        return False
    return True


def upload_file(file, bucket_name, object_name=None):
    """Upload a file to an S3 bucket
    :param file: file to upload
    :param bucket_name: Bucket to upload to s3 bucket
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file)

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(file, bucket_name, object_name)
        object_name = None
    except ClientError as e:
        logging.error(e)
        return False
    return True


if __name__ == "__main__":
    bucket_name = "3nic-2vm-ha-glm-pubvip-backauto-bucket"
    python_file = 'CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_SERVER_PACKAGE.zip'
    status = create_bucket(bucket_name)
    if status:
        upload_status = upload_file(python_file, bucket_name, object_name=None)
        if upload_status:
            print("File uploaded in S3 bucket successfully.")
        else:
            print("Failed to upload file in S3 bucket.")
    else:
        print("Failed to create bucket.")
