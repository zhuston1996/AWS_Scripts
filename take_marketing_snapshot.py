import boto3
from datetime import date
import time


ec2_resource = boto3.resource('ec2')
ec2_client = boto3.client('ec2')

def prompt_user():
    instance_id = instance_id = input("Enter the instance id:")
    instance = ec2_resource.Instance(instance_id)
    return instance, instance_id


def get_ec2_instance_name(instance):
    for tag in instance.tags:
        if tag['Key'] == 'Name':
            print("The instance we will snapshot is: ", tag['Value'])
            return tag['Value']


def build_ami_name(instance_id):
    today = date.today()
    string_date = str(today.strftime("__%m-%d-%Y"))
    
    instance_name = get_ec2_instance_name(instance_id) 
    sep = '__'
    stripped_name = instance_name.split(sep, 1)[0]

    created_ami_name = stripped_name + string_date
    print('The new AMI name will be: ', created_ami_name)
    return created_ami_name


def create_ami_image(instance, instance_id, ami_name):
    ami = instance.create_image(InstanceId=instance_id, NoReboot=True, Name=ami_name)
    ami_id = str(ami.id)
    print('This is the id of the AMI we created:', ami_id)
    return ami_id


def check_ami_status(ami_id): 
    image = "Checking if AMI is ready to use..."
    while (image != ami_id):
        response = ec2_client.describe_images(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ],
            ImageIds=[
                ami_id,
            ],
            Owners=[
                '144487101178',
            ],
            IncludeDeprecated=True
        )
        
        if (len(response['Images']) > 0):
            image = str(response['Images'][0]['ImageId'])
            print("Created AMI Image is ready to use:", image)
        else:
            print('AMI not ready yet')
        time.sleep(10)


def build_new_instance(ami,instance_name):
    print("Working on new EC2 Instance")

    instance_list = ec2_resource.create_instances(
        ImageId=ami,
        MinCount=1,
        MaxCount=1,
        InstanceType="m5.xlarge",
        KeyName="marketingWordpress",
        SecurityGroupIds=[
            'sg-07a7be3646212a08d'
        ],
        #SubnetId="subnet-04c795e32edeeb276",
        TagSpecifications=[
        {
            'ResourceType':'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': instance_name
                },
            ]
        },
        ],
    )
    for instance in instance_list:
        print('New instance is: ', instance.id)
        return instance


def stop_new_running_instance(instance):
    instance_id = list()
    instance_id.append(instance.id)
    state ="No State"

    print('Checking EC2 state, stopping once running...')
    while(state != 'running'):
        response = ec2_client.describe_instance_status(
            InstanceIds=instance_id
        )
        time.sleep(10)
        if(len(response['InstanceStatuses']) > 0):
            state =response['InstanceStatuses'][0]['InstanceState']['Name']
        else:
            print("EC2 not ready to stop yet")

    print('State: ', state)
    time.sleep(10)

    print('Will now stop the instance')
    response= ec2_client.stop_instances(
        InstanceIds=[
            instance_id[0]
        ]
    )
    print("State: stopped")


def __main__():
    instance,instance_id = prompt_user()

    ami_name = build_ami_name(instance)
    ami_id = create_ami_image(instance, instance_id, ami_name)
    check_ami_status(ami_id)

    instance = build_new_instance(ami_id,ami_name)
    new_instance_id = str(instance.id)
    stop_new_running_instance(instance)
    
    print("New Created ami {} and created instance {} from it".format(ami_id,new_instance_id))
__main__()