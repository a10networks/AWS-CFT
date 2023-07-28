import logging
import os
import boto3
from botocore.exceptions import ClientError


def create_bucket(bucket_name, region):
    """Create an S3 bucket
    :param bucket_name: Bucket to create
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        s3_client = boto3.client('s3')
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
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
    bucket_name = input("Enter bucket name: ")
    region = input("Enter region: ")
    python_file = 'CFT_TMPL_3NIC_2VM_HA_GLM_PUBVIP_BACKAUTO_SERVER_PACKAGE.zip'
    if not region.strip() or not bucket_name.strip():
        raise("Please provide the region value or bucket name")
    status = create_bucket(bucket_name.lower(), region.lower())
    if status:
        upload_status = upload_file(python_file, bucket_name, object_name=None)
        if upload_status:
            print("File uploaded in S3 bucket successfully.")
        else:
            print("Failed to upload file in S3 bucket.")
    else:
        print("Failed to create bucket.")
