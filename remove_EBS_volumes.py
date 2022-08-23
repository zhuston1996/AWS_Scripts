#!/usr/bin/python

import boto3
from pprint import pprint
import dotenv
import os

dotenv.load_dotenv()

# create boto3 client for ec2
client = boto3.client('ec2',
                      region_name=os.getenv('AWS_REGION'),
                      aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                      aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))

volumes_to_delete = list()

# call describe_volumes() method of client to get the details of all ebs volumes in given region
# if you have large number of volumes then get the volume detail in batch by using nextToken and process accordingly
volume_detail = client.describe_volumes()

# process each volume in volume_detail
if volume_detail['ResponseMetadata']['HTTPStatusCode'] == 200:
    for each_volume in volume_detail['Volumes']:
        # some logging to make things clear about the volumes in your existing system
        print("Working for volume with volume_id: ", each_volume['VolumeId'])
        print("State of volume: ", each_volume['State'])
        print("Attachment state length: ", len(each_volume['Attachments']))
        print(each_volume['Attachments'])
        print("--------------------------------------------")
        # figuring out the unused volumes
        # the volumes which do not have 'Attachments' key and their state is 'available' is considered to be unused
        if len(each_volume['Attachments']) == 0 and each_volume['State'] == 'available':
            volumes_to_delete.append(each_volume['VolumeId'])

# these are the candidates to be deleted by maintaining waiters for them
pprint(volumes_to_delete)
	
