import boto3, datetime, argparse, sys

def main(sendit, dryrun):
    AWSAccountId = boto3.client('sts').get_caller_identity().get('Account')
    t = datetime.datetime.utcnow()
    filename = f'Output/[{AWSAccountId}]-{t.strftime("%m")}-{t.strftime("%d")}-{t.year}-{t.strftime("%H%M%S")}UTC_gp2_conversion_information.txt'
    count = 0
    regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]

    # Create new blank gp2_volume_information.txt file.
    f = open(filename, "x")
    f.write(f'\n###########################################################\nGP2 to GP3 Conversion.\nAccount: {AWSAccountId}\n###########################################################')

    for region in regions:
        # Initializing EC2 boto 3 client
        ec2_client = boto3.client('ec2', region_name=region)
        f.write(f'\n{region}:\n')
        # Retrieving all volumes that are currently gp2
        response = ec2_client.describe_volumes(Filters=[{'Name': 'volume-type', 'Values': ['gp2']}])

        # Iterating over each gp2 volume
        for volume in response['Volumes']:
            volumeInfo = ec2_client.describe_volumes(Filters=[{'Name': 'volume-id', 'Values': [volume['VolumeId']]}])
            for y in volumeInfo['Volumes']:
                try:
                    if len(y['Attachments']) < 1:
                        # Writing output to file.
                        f.write(f'{str(volume["VolumeId"])} has {str(volume["Iops"])} IOPS. INFO (Not attached to any instance...)\n')
                    else:
                        for tag in y['Tags']: 
                            if tag['Key'] == 'Name':
                                # Writing output to file.
                                f.write(f'{str(volume["VolumeId"])} has {str(volume["Iops"])} IOPS. Info ( {str(tag["Value"])} || {str(y["Attachments"][0]["InstanceId"])} )\n')
                except KeyError as ke:
                    # Writing output to file.
                    f.write(f'{str(volume["VolumeId"])} has {str(volume["Iops"])} IOPS. Info ( {str(y["Attachments"][0]["InstanceId"])} )\n')

            
            if dryrun:
                # Modifying volume from gp2 to gp3.
                #GP2 Drive Throughput Information. (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html)
                    # The throughput limit is between 128 MiB/s and 250 MiB/s, depending on the volume size.
                    # Volumes smaller than or equal to 170 GiB deliver a maximum throughput of 128 MiB/s.
                    # Volumes larger than 170 GiB but smaller than 334 GiB deliver a maximum throughput of 250 MiB/s if burst credits are available.
                    # Volumes larger than or equal to 334 GiB deliver 250 MiB/s regardless of burst credits.
                if volume['Iops'] < 3000:
                    if volume['Size'] < 178:
                        f.write(f'{str(volume["VolumeId"])} WOULD BE CONVERTED to GP3 with 3000 IOPS with no throughput defined.\nVolume Size: {volume["Size"]}\n')
                    else:
                        f.write(f'{str(volume["VolumeId"])} WOULD BE CONVERTED to GP3 with 3000 IOPS with throughput defined at 250 MiB/s.\nVolume Size: {volume["Size"]}\n')
                else:
                    if volume['Size'] < 178:
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with {str(volume["Iops"])} IOPS and no throughput defined.\nVolume Size: {volume["Size"]}\n')
                    else:
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with {str(volume["Iops"])} IOPS and throughput defined at 250 MiB/s.\nVolume Size: {volume["Size"]}\n')
            if sendit:
                # Modifying volume from gp2 to gp3.
                if volume['Iops'] < 3000:
                    if volume['Size'] < 178:
                        ec2_client.modify_volume(VolumeId=volume['VolumeId'],VolumeType='gp3')
                        # Writing information to file.
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with 3000 IOPS and no throughput defined.\nVolume Size: {volume["Size"]}\n')
                    else:
                        ec2_client.modify_volume(VolumeId=volume['VolumeId'],Throughput=250,VolumeType='gp3')
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with 3000 IOPS and throughput defined at 250 MiB/s.\nVolume Size: {volume["Size"]}\n')      
                else:
                    if volume['Size'] < 178:
                        ec2_client.modify_volume(VolumeId=volume['VolumeId'],Iops=volume["Iops"], VolumeType='gp3')
                        # Writing information to file.
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with {str(volume["Iops"])} IOPS and no throughput defined.\nVolume Size: {volume["Size"]}\n')
                    else:
                        ec2_client.modify_volume(VolumeId=volume['VolumeId'],Throughput=250,Iops=volume["Iops"],VolumeType='gp3')
                        # Writing information to file.
                        f.write(f'{str(volume["VolumeId"])} converting to GP3 with {str(volume["Iops"])} IOPS and throughput defined at 250 MiB/s.\nVolume Size: {volume["Size"]}\n')
            count += 1

        if dryrun:
            # Writing to file how many volumes were modified
            f.write("\n\n###########################################################\n"+ str(count) + " volumes would be modified.\n###########################################################")
        if sendit:
            f.write("\n\n###########################################################\n"+ str(count) + " volumes modified.\n###########################################################")
    
    # Closing file.
    f.close()



if __name__ == "__main__":
    dryrun = False
    sendit = False
    parser = argparse.ArgumentParser(description='Convert gp2 ebs volumes to gp3 ebs volumes.')
    parser.add_argument('-d', "--dryrun", dest='dryrun', action='store_true',
                        help='Dry run the script, not changing or modifying anything in AWS.')
    parser.add_argument('-s', "--sendit", dest='sendit', action='store_true',
                        help='Run the script, upgrading the gp2 volumes to gp3 in AWS. Full send.')

    args = parser.parse_args()
    if args.dryrun and args.sendit:
        print("Don\'t use both arguments.... ")
        sys.exit()
    elif not args.dryrun and not args.sendit:
        parser.print_help()
        sys.exit()
    elif args.dryrun and not args.sendit:
        dryrun = True
    elif args.sendit and not args.dryrun:
        val = input("Sending it! Are you sure? (y/n)")
        if val == "n":
            print("Good thing I had this check... Exiting...")
            sys.exit()
        if val != "y":
            print("You must enter 'y' or 'n'. Try again.")
            sys.exit()
        sendit = True
    main(sendit, dryrun)