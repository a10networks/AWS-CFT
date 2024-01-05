"""
Script to create a new s3 bucket or use existing bucket to upload python zip package for
lambda function.

Author: vgautam@a10networks.com
"""
import logging
import os
import boto3
from botocore.exceptions import ClientError

# name of bucket to be created
BUCKET_NAME = input("Enter bucket name: ")
# region to create bucket
# Specifies the region where the bucket will be created.
# If you don't specify a region, the bucket will be created in US Standard.
# 'EU'|'eu-west-1'|'us-west-1'|'us-west-2'|'ap-south-1'|'ap-southeast-1'|'ap-southeast-2'|'ap-northeast-1'|'sa-east-1'|'cn-north-1'|'eu-central-1'
BUCKET_REGION = input("Enter region: ")

if not BUCKET_REGION.strip() or not BUCKET_NAME.strip():
    raise Exception("Please provide the region value or bucket name")
# zip file name to upload
ZIP_FILE = 'AUTOSCALE_SERVER_PACKAGE.zip'


def create_bucket(bucket_name, region):
    """Create an S3 bucket
    :param bucket_name: Bucket to create
    :param region: region where to create bucket
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
    status = create_bucket(BUCKET_NAME.lower(), BUCKET_REGION.lower())
    if status:
        upload_status = upload_file(ZIP_FILE, BUCKET_NAME, object_name=None)
        if upload_status:
            print("File uploaded in S3 bucket successfully.")
        else:
            print("Failed to upload file in S3 bucket.")
    else:
        print("Failed to create bucket.")
