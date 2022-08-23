import boto3
import sys
import pprint

##
# USAGE: python3 AWS_ECS_enable-capacity-provider.py {ASG NAME} {CLUSTER NAME}
##


def main():
    autoscaling = boto3.client('autoscaling')
    ecs = boto3.client('ecs')

    asg_name = sys.argv[1]
    cluster_name = sys.argv[2]

    if asg_name is None:
        raise ValueError("Name of the ASG is required.")

    asg_results = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[
            asg_name
        ])
    if len(asg_results['AutoScalingGroups']) == 0:
        print(
            f"NO results found for asg_name {asg_name}. \nResult: {asg_results}")
        exit()
    if len(asg_results['AutoScalingGroups']) > 1:
        print(
            f"More than one ASG found for asg_name {asg_name}. \nResult: {asg_results}")
        exit()
    asg = asg_results['AutoScalingGroups'][0]
    asg_arn = asg['AutoScalingGroupARN']

    if asg['NewInstancesProtectedFromScaleIn'] == False:
        print('NewInstancesProtectedFromScaleIn is currently False, setting to True')
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            NewInstancesProtectedFromScaleIn=True)

    print('Ensuring tag  AmazonECSManaged is on the ASG')
    autoscaling.create_or_update_tags(
        Tags=[
            {
                'ResourceId': asg_name,
                'ResourceType': 'auto-scaling-group',
                'Key': ' AmazonECSManaged',
                'Value': '',
                'PropagateAtLaunch': True
            },
        ]
    )

    print("CREATING CAPACITY PROVIDER")
    cp = ecs.create_capacity_provider(
        name=f"{cluster_name}_CapacityProvider",
        autoScalingGroupProvider={
            'autoScalingGroupArn': asg_arn,
            'managedScaling': {
                'status': 'ENABLED',
                'targetCapacity': 50,
                'minimumScalingStepSize': 1,
                'maximumScalingStepSize': 100,
                'instanceWarmupPeriod': 120
            },
            'managedTerminationProtection': 'ENABLED'
        },
    )
    pprint.pprint(cp)
    print("ADDING CAPACITY PROVIDER TO CLUSTER")
    put_cp = ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[
            cp['capacityProvider']['name'],
        ],
        defaultCapacityProviderStrategy=[
            {
                'capacityProvider': cp['capacityProvider']['name'],
                'weight': 1,
                'base': 1
            },
        ]
    )
    pprint.pprint(put_cp)


main()
