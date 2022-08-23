#   Lambda Name     : UpdateGlobalAWSIPs
#   Version         : 1.0.0.0
#   Date            : 27-June-2020
#   Details         : 1. Updating AWS service IPs in the Security Groups.
#                     2. Require "All Traffic" for the first time invocation and it will be removed once execution completes.
#   Runtime         : Python 2.7
#   Momory          : 128 MB
#   Timeout         : 1 Min.

import boto3
import hashlib
import json
import urllib2
import os
import sys
import traceback

# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = { 'Http' : 80, 'Https': 443 }
SG_CF_Global_ID = os.environ.get("SG_CF_Global")
SG_CF_Region_ID = os.environ.get("SG_CF_Region")
SG_AWS_Services_ID = os.environ.get("SG_AWSService1")
SG_AWS_Services_2_ID = os.environ.get("SG_AWSService2")
SG_EC2_ID  = os.environ.get("SG_EC2")

SERVICE_LIST = os.environ.get("Service_List")
REGION_LIST = os.environ.get("Region_List")

SG_Max_Limit  = os.environ.get("SG_Max_Limit")
print(SG_Max_Limit)
if str(SG_Max_Limit) == 'None':
    SG_Max_Limit = 200
else:
    SG_Max_Limit = int(SG_Max_Limit)

#REGION_LIST = "us-east-1,us-east-2,us-west-1,us-west-2,ap-south-1"
#REGION_LIST = "us-east-1"

Service = []
Region  = []
ServiceLen = 0
RegionLen = 0

def lambda_handler(event, context):

    print("MaxLimit : " + str(SG_Max_Limit))

    print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    #Allow All Traffic
    #print("Updating the EC2PSG SG...")
    #result = update_security_groups_for_proxy(SG_EC2PG_ID)
    #print("EC2PSG update completed...")

    url = message['url']
    print("Updating from " + url)
    response = urllib2.urlopen(url)
    resJson = json.loads(response.read())
    ip_ranges_master = resJson
    #print(ip_ranges_master)
    Service = SERVICE_LIST.split(",")
    Region  = REGION_LIST.split(",")
    #Remove All Traffic
    #print("Removing All Traffic...")
    result = remove_security_groups_for_proxy(SG_CF_Global_ID)
    result = remove_security_groups_for_proxy(SG_CF_Region_ID)
    result = remove_security_groups_for_proxy(SG_AWS_Services_ID)
    result = remove_security_groups_for_proxy(SG_AWS_Services_2_ID)
    print("All Traffic removed...")
    isException = 0
    try:
        # CF_Global
        global_cf_ranges = get_ranges_for_service_global(ip_ranges_master, "CLOUDFRONT", "GLOBAL", Region)
        ip_ranges = { "GLOBAL": global_cf_ranges }
        result = update_security_groups_global(ip_ranges, SG_CF_Global_ID, "CLOUDFRONT-GLOBAL", "INGRESS")

        # CF_Region
        region_cf_ranges = get_ranges_for_service(ip_ranges_master, "CLOUDFRONT", "REGION", Region)
        ip_ranges = { "REGION": region_cf_ranges }
        result = update_security_groups(ip_ranges, SG_CF_Region_ID, "CLOUDFRONT-REGION", "INGRESS", "")

        # AWS_Services
        region_cnt_ranges = get_ranges_for_service_list(ip_ranges_master, Service, "REGION", Region)
        ip_ranges = { "REGION": region_cnt_ranges }
        result = update_security_groups_AWSSerive(ip_ranges, SG_AWS_Services_ID, "S3/CONNECT-REGION/EC2", "EGRESS", SG_AWS_Services_2_ID)
    except Exception as ex:
        print("Exception occurred : " + str(ex))
        # Get current system exception
        ex_type, ex_value, ex_traceback = sys.exc_info()
        # Extract unformatter stack traces as tuples
        trace_back = traceback.extract_tb(ex_traceback)
        # Format stacktrace
        stack_trace = list()

        for trace in trace_back:
            stack_trace.append("File : %s , Line : %d, Func.Name : %s, Message : %s" % (trace[0], trace[1], trace[2], trace[3]))

        print("Exception type : " + str(ex_type.__name__))
        #print("Exception message : " + str(ex_value))
        print("Stack trace : " + str(stack_trace))
        isException = 1
        print("Exception occurred and hence retun without removing 'All Traffic' from 'AECPrivateGroup' Security Group...")

    if (SG_Max_Limit > 0 and isException == 0) :
        #Remove All Traffic
        #print("Removing 'All Traffic' from 'AECPrivateGroup' Security Group...")
        result = remove_security_groups_for_proxy(SG_EC2_ID)
        print("Removed 'All Traffic' from 'AECPrivateGroup' Security Group...")

    return result

def get_ip_groups_json(url, expected_hash):
    print("Updating from " + url)

    response = urllib2.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, Service, subset, Region):
    #print("Inside get_ranges_for_service")
    service_ranges = list()
    Region.append('ap-south-1')
    CFRegionList = "{ "
    for prefix in ranges['prefixes']:
        for RegionItem in Region:
            if prefix['service'] == Service and ( prefix['region'] == str(RegionItem)):
                CFRegionList = CFRegionList + str(prefix['ip_prefix']) + ", "
                #print('Found ' + Service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix'])
                prefix['ip_prefix'] = prefix['ip_prefix'] + "," + prefix['service'] + "," + prefix['region']
                service_ranges.append(prefix['ip_prefix'])

    CFRegionList = CFRegionList[:-1]
    CFRegionList = CFRegionList[:-1]
    CFRegionList = CFRegionList + " }"
    print("CloudFront Region IPs [Public SG]: " + CFRegionList)

    return service_ranges

def get_ranges_for_service_global(ranges, Service, subset, Region):
    #print("Inside get_ranges_for_service")
    service_ranges = list()
    CFGlobalList = "{ "
    for prefix in ranges['prefixes']:
        if prefix['service'] == Service and ( prefix['region'] == "GLOBAL"):
            CFGlobalList = CFGlobalList + str(prefix['ip_prefix']) + ", "
            #print('Found ' + Service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix'])
            prefix['ip_prefix'] = prefix['ip_prefix'] + "," + prefix['service'] + "," + prefix['region']
            service_ranges.append(prefix['ip_prefix'])

    CFGlobalList = CFGlobalList[:-1]
    CFGlobalList = CFGlobalList[:-1]
    CFGlobalList = CFGlobalList + " }"
    print("CloudFront Global IPs [Public SG]: " + CFGlobalList)
    return service_ranges

def get_ranges_for_service_list(ranges, Service, subset, Region):
    #print("Inside get_ranges_for_service")
    service_ranges = list()
    Region.append('GLOBAL')
    S3ConnectRegionList = "{ "
    for prefix in ranges['prefixes']:
        for ServiceItem in Service:
            for RegionItem in Region:
                if prefix['service'] == ServiceItem and prefix['region'] == str(RegionItem):
                    S3ConnectRegionList = S3ConnectRegionList + str(prefix['ip_prefix']) + ", "
                    #print('Found ' + ServiceItem + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix'])
                    prefix['ip_prefix'] = prefix['ip_prefix'] + "," + prefix['service'] + "," + prefix['region']
                    service_ranges.append(prefix['ip_prefix'])

    S3ConnectRegionList = S3ConnectRegionList[:-1]
    S3ConnectRegionList = S3ConnectRegionList[:-1]
    S3ConnectRegionList = S3ConnectRegionList + " }"
    print("S3 and Connect Region IPs [Private SG]: " + S3ConnectRegionList)
    return service_ranges

def update_security_groups_global(new_ranges, SG_ID, Desc, Type):
    #print("Inside update_security_groups")
    client = boto3.client('ec2')
    #print(new_ranges)
    global_http_group = get_security_groups_for_update(client, SG_ID)
    #print ('Found ' + str(len(global_http_group)) + ' SecurityGroup to update')

    result = list()
    global_http_updated = 0

    for group in global_http_group:
        if update_security_group(client, group, new_ranges["GLOBAL"], INGRESS_PORTS['Https'], "CLOUDFRONT-GLOBAL", Type, ""):
            global_http_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' SecurityGroup')

    return result

def update_security_groups(new_ranges, SG_ID, Desc, Type, SecondarySG_ID):
    #print("Inside update_security_groups")
    client = boto3.client('ec2')
    SecondarySG_IDVal = str(SecondarySG_ID)
    #print(SecondarySG_IDVal)
    global_http_group = get_security_groups_for_update(client, SG_ID)
    found = 0
    SecondaryGroup = list()
    if len(SecondarySG_ID) > 2:
        found = 1
        global_http_group2 = get_security_groups_for_update(client, SecondarySG_ID)
        for group2 in global_http_group2:
            SecondaryGroup = group2
            break
    #print ('Found ' + str(len(global_http_group)) + ' SecurityGroup to update')

    result = list()
    global_http_updated = 0

    if found == 1:
        for group in global_http_group:
            if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, SecondaryGroup):
                global_http_updated += 1
                result.append('Updated ' + group['GroupId'])
    else:
        for group in global_http_group:
            if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, ""):
                global_http_updated += 1
                result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' SecurityGroup')

    return result

def update_security_groups_AWSSerive(new_ranges, SG_ID, Desc, Type, SecondarySG_ID):
    #print("Inside update_security_groups")
    client = boto3.client('ec2')
    SecondarySG_IDVal = str(SecondarySG_ID)
    #print(SecondarySG_IDVal)
    global_http_group = get_security_groups_for_update(client, SG_ID)
    found = 0
    SecondaryGroup = list()
    if len(SecondarySG_ID) > 2:
        found = 1
        global_http_group2 = get_security_groups_for_update(client, SecondarySG_ID)
        for group2 in global_http_group2:
            SecondaryGroup = group2
            break
    #print ('Found ' + str(len(global_http_group)) + ' SecurityGroup to update')

    result = list()
    global_http_updated = 0
    #print(found)
    if found == 1:
        #print(global_http_group)
        for group in global_http_group:
            if len(group['IpPermissionsEgress']) > 0:
                if update_security_group_AWSService(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, SecondaryGroup):
                    global_http_updated += 1
                    result.append('Updated ' + group['GroupId'])
            else:
                if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, SecondaryGroup):
                    global_http_updated += 1
                    result.append('Updated ' + group['GroupId'])

    else:
        for group in global_http_group:
            if len(group['IpPermissionsEgress']) > 0:
                if update_security_group_AWSService(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, ""):
                    global_http_updated += 1
                    result.append('Updated ' + group['GroupId'])
            else:
                if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https'], Desc, Type, ""):
                    global_http_updated += 1
                    result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' SecurityGroup')

    return result

def update_security_groups_for_proxy(SG_ID):
    #print("Inside update_security_groups")
    client = boto3.client('ec2')

    global_http_group = get_security_groups_for_update(client, SG_ID)

    #print ('Found ' + str(len(global_http_group)) + ' SecurityGroup to update')

    result = list()
    global_http_updated = 0

    for group in global_http_group:
        if update_security_group_for_proxy(client, group, INGRESS_PORTS['Https'], "All Traffic"):
            global_http_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' SecurityGroup')

    return result

def remove_security_groups_for_proxy(SG_ID):
    #print("Inside update_security_groups")
    client = boto3.client('ec2')
    global_http_group = get_security_groups_for_update(client, SG_ID)

    #print ('Found ' + str(len(global_http_group)) + ' SecurityGroup to update')

    result = list()
    global_http_updated = 0

    for group in global_http_group:
        if remove_security_group_for_proxy(client, group, INGRESS_PORTS['Https'], "All Traffic"):
            global_http_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' SecurityGroup')
    return result

def update_security_group(client, group, new_ranges, port, Desc, Type, group2):
    added = 0
    removed = 0
    groupVal = list()

    #print("----------- Remove All rules from AEC-AWSService-1 & AEC-AWSService-2 Security Groups ----------")

    if (SG_Max_Limit == -1 or SG_Max_Limit == -3) and Desc != 'CLOUDFRONT-GLOBAL' and Desc != 'CLOUDFRONT-REGION':
            print("Removing from SG_AWSService1")
            if len(group['IpPermissionsEgress']) > 0:
                for permission in group['IpPermissionsEgress']:
                    if permission['IpProtocol'] != '-1':
                        if permission['FromPort'] <= port and permission['ToPort'] >= port :
                            to_revoke = list()
                            for range in permission['IpRanges']:
                                cidr = range['CidrIp']
                                to_revoke.append(range)
                                print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                            removed += revoke_permissions(client, group, permission, to_revoke, Type)
            print("Removing from SG_AWSService2")
            if len(group2['IpPermissionsEgress']) > 0:
                for permission in group2['IpPermissionsEgress']:
                    if permission['IpProtocol'] != '-1':
                        if permission['FromPort'] <= port and permission['ToPort'] >= port :
                            to_revoke = list()
                            for range in permission['IpRanges']:
                                cidr = range['CidrIp']
                                to_revoke.append(range)
                                print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                            removed += revoke_permissions(client, group2, permission, to_revoke, Type)


    #print("----------- Remove All rules from AECCloudFrontGlobalIP & AECCloudFrontRegionIP Security Groups ----------")

    if (SG_Max_Limit == -2 or SG_Max_Limit == -3) and Desc == 'CLOUDFRONT-GLOBAL':
        print("Removing from AECCloudFrontGlobalIP")
        if len(group['IpPermissions']) > 0:
            for permission in group['IpPermissions']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        to_revoke = list()
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            to_revoke.append(range)
                            print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        removed += revoke_permissions(client, group, permission, to_revoke, Type)

    if (SG_Max_Limit == -2 or SG_Max_Limit == -3) and Desc == 'CLOUDFRONT-REGION':
        print("Removing from AECCloudFrontRegionIP")
        if len(group['IpPermissions']) > 0:
            for permission in group['IpPermissions']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        to_revoke = list()
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            to_revoke.append(range)
                            print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        removed += revoke_permissions(client, group, permission, to_revoke, Type)

    if (SG_Max_Limit < 0):
        return 0

    #print (str(len(new_ranges_Dup)))
    new_ranges = list( dict.fromkeys(new_ranges) )
    #print (str(len(new_ranges_Dup)))

    new_ranges_Dup = list(new_ranges)
    #print("update_security_group")
    for i, item in enumerate(new_ranges_Dup):
        range1 = item
        strRange1 = str(range1)
        FirstComma = strRange1.find(',',0)
        SecondComma = strRange1.find(',',FirstComma+1)
        IP = strRange1[0:FirstComma]
        ServiceName = strRange1[FirstComma+1:SecondComma]
        ServiceRegion = strRange1[SecondComma+1:len(range1)]
        range1 = IP
        new_ranges_Dup[i] = range1

    if Type == "INGRESS":
        if len(group['IpPermissions']) > 0:
            groupIngress = group['IpPermissions']
            #print("Ingress")
            #print(groupIngress)
            groupVal = groupIngress
        else:
            groupVal = []

    elif Type == "EGRESS":
        if len(group['IpPermissionsEgress']) > 0:
            groupEgress = group['IpPermissionsEgress']
            #print("Egress")
            #print(groupEgress)
            groupVal = groupEgress

        if len(group2['IpPermissionsEgress']) > 0:
            groupEgress2 = group['IpPermissionsEgress']
            groupEgress.append(groupEgress2)
        else:
            groupVal = []

    if len(groupVal) > 0:
        for permission in groupVal:
            if permission['FromPort'] <= port and permission['ToPort'] >= port :
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                to_addDup = list()

                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges_Dup.count(cidr) == 0:
                        to_revoke.append(range)
                        print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))

                for range in new_ranges:
                    leng = len(range)
                    range1 = range
                    strRange1 = str(range1)
                    FirstComma = strRange1.find(',',0)
                    SecondComma = strRange1.find(',',FirstComma+1)
                    IP = strRange1[0:FirstComma]
                    ServiceName = strRange1[FirstComma+1:SecondComma]
                    ServiceRegion = strRange1[SecondComma+1:len(range1)]
                    range1 = IP
                    Desc = ServiceName + " / " + ServiceRegion
                    if old_prefixes.count(range1) == 0:
                        to_addDup.append({ 'CidrIp': range1, 'Description':Desc })
                        found = 0
                        if len(to_add) >= 1:
                            for to_addItem in to_add:
                                str1 = range1
                                str2 = to_addItem['CidrIp']
                                #print(str1, str2)
                                if str1 == str2:
                                    found = 1
                                    #print(group['GroupId'] + ": Already exists " + range + ":" + str(permission['ToPort']))
                                    break
                                else:
                                    found = 0
                            if found == 1:
                                print(group['GroupId'] + ": Already exists " + range + ":" + str(permission['ToPort']))
                            else:
                                to_add.append({ 'CidrIp': range1, 'Description':Desc })
                                print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))
                                to_addDup.pop()
                        else:
                            to_add.append({ 'CidrIp': range1, 'Description':Desc })
                            print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))
                            to_addDup.pop()

                removed += revoke_permissions(client, group, permission, to_revoke, Type)
                added += add_permissions(client, group, permission, to_add, Type, group2)
    else:
        to_add = list()
        to_addDup = list()
        for range in new_ranges:
            leng = len(range)
            range1 = range
            strRange1 = str(range1)
            FirstComma = strRange1.find(',',0)
            SecondComma = strRange1.find(',',FirstComma+1)
            IP = strRange1[0:FirstComma]
            ServiceName = strRange1[FirstComma+1:SecondComma]
            ServiceRegion = strRange1[SecondComma+1:len(range1)]
            range1 = IP
            Desc = ServiceName + " / " + ServiceRegion
            to_addDup.append({ 'CidrIp': range1, 'Description':Desc })
            found = 0
            if len(to_add) >= 1:
                for to_addItem in to_add:
                    str1 = range1
                    str2 = to_addItem['CidrIp']
                    #print(str1, str2)
                    range1 = range
                    if str1 == str2:
                        found = 1
                        #print(group['GroupId'] + ": Already exists " + range + ":" + str(port))
                        break
                    else:
                        found = 0
                if found == 1:
                    print(group['GroupId'] + ": Already exists " + range + ":" + str(port))
                else:
                    strRange1 = str(range1)
                    FirstComma = strRange1.find(',',0)
                    SecondComma = strRange1.find(',',FirstComma+1)
                    IP = strRange1[0:FirstComma]
                    ServiceName = strRange1[FirstComma+1:SecondComma]
                    ServiceRegion = strRange1[SecondComma+1:len(range1)]
                    range1 = IP
                    Desc = ServiceName + " / " + ServiceRegion
                    for to_addItem in to_add:
                        str1 = range1
                        str2 = to_addItem['CidrIp']
                        #print(str1, str2)
                        if str1 == str2:
                            found = 1
                            #print(group['GroupId'] + ": Already exists " + range + ":" + str(port))
                            break
                        else:
                            found = 0
                    if found == 1:
                        print(group['GroupId'] + ": Already exists " + range + ":" + str(port))
                    else:
                        to_add.append({ 'CidrIp': range1, 'Description':Desc })
                        print(group['GroupId'] + ": Adding " + range + ":" + str(port))
                        to_addDup.pop()

            else:
                to_add.append({ 'CidrIp': range1, 'Description':Desc })
                print(group['GroupId'] + ": Adding  " + range + ":" + str(port))
                to_addDup.pop()

        permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add, Type, group2)

    #print (group['GroupId'] + ": Count " + str(len(new_ranges)) + ", Added " + str(added) + ", Revoked " + str(removed))
    print (group['GroupId'] + ": Count in JSON " + str(len(new_ranges)) + ", Actual Count " + str(len(new_ranges_Dup)) + ", Duplicate Count " + str(len(new_ranges) - len(new_ranges_Dup)) + ", Added " + str(added) + ", Revoked " + str(removed))

    return (added > 0 or removed > 0)

def update_security_group_AWSService(client, group, new_ranges, port, Desc, Type, group2):
    added = 0
    removed = 0
    groupVal = list()
    new_ranges_Dup = []
    OnlyGroup1 = 0
    SG_Count_G1 = 0
    SG_ToAdd_G1 = 0
    SG_ToRevoke_G1 = 0
    SG_Count_G2 = 0
    SG_ToAdd_G2 = 0
    SG_ToRevoke_G2 = 0
    old_prefixes_G1 =[]
    to_add_G1 = []
    to_revoke_G1 = []
    old_prefixes_G2 =[]
    to_add_G2 = []
    to_revoke_G2 = []

    MaxLimit = int(SG_Max_Limit)
    #print(MaxLimit)
    #print("----------- Remove All rules from AEC-AWSService-1 & AEC-AWSService-2 Security Groups ----------")
    if SG_Max_Limit == -1 or SG_Max_Limit == -3:
        print("Removing from SG_AWSService1")
        if len(group['IpPermissionsEgress']) > 0:
            for permission in group['IpPermissionsEgress']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        to_revoke = list()
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            to_revoke.append(range)
                            print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        removed += revoke_permissions(client, group, permission, to_revoke, Type)

        print("Removing from SG_AWSService2")
        if len(group2['IpPermissionsEgress']) > 0:
            for permission in group2['IpPermissionsEgress']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        to_revoke = list()
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            to_revoke.append(range)
                            print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        removed += revoke_permissions(client, group2, permission, to_revoke, Type)
        return (added > 0 or removed > 0)

    #print (str(len(new_ranges_Dup)))
    new_ranges = list( dict.fromkeys(new_ranges) )
    #print (str(len(new_ranges_Dup)))

    for item in new_ranges:
        range1 = item
        strRange1 = str(range1)
        FirstComma = strRange1.find(',',0)
        SecondComma = strRange1.find(',',FirstComma+1)
        IP = strRange1[0:FirstComma]
        ServiceName = strRange1[FirstComma+1:SecondComma]
        ServiceRegion = strRange1[SecondComma+1:len(range1)]
        range1 = IP
        new_ranges_Dup.append(range1)

    #print (str(len(new_ranges_Dup)))
    new_ranges_Dup = list( dict.fromkeys(new_ranges_Dup) )
    #print (str(len(new_ranges_Dup)))

    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in permission['IpRanges']:
                        cidr = range['CidrIp']
                        old_prefixes_G1.append(cidr)
        SG_Count_G1 = len(old_prefixes_G1)

    if len(group2['IpPermissionsEgress']) > 0:
        for permission in group2['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in permission['IpRanges']:
                        cidr = range['CidrIp']
                        old_prefixes_G2.append(cidr)
        SG_Count_G2 = len(old_prefixes_G2)

    #print(SG_Count_G1)
    #print(SG_Count_G2)
    #print(old_prefixes_G1)
    #print(old_prefixes_G2)

    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in permission['IpRanges']:
                        cidr = range['CidrIp']
                        if new_ranges_Dup.count(cidr) == 0:
                            to_revoke_G1.append(range)
                            SG_ToRevoke_G1 = SG_ToRevoke_G1 + 1
                            print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        #else:
                            #print(group['GroupId'] + ": Already exists " + cidr + ":" + str(permission['ToPort']))

    SG_ToAdd_G1 = SG_ToRevoke_G1

    if len(group2['IpPermissionsEgress']) > 0:
        for permission in group2['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in permission['IpRanges']:
                        if new_ranges_Dup.count(cidr) == 0:
                            to_revoke_G2.append(range)
                            SG_ToRevoke_G2 = SG_ToRevoke_G2 + 1
                            print(group2['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))
                        #else:
                            #print(group2['GroupId'] + ": Already exists " + cidr + ":" + str(permission['ToPort']))

    SG_ToAdd_G2 = SG_ToRevoke_G2

    #print("----------- Starts ----------")
    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in new_ranges_Dup:
                        if old_prefixes_G1.count(range) == 0 and old_prefixes_G2.count(range) == 0:
                            to_add_G1.append({ 'CidrIp': range, 'Description':Desc })
                            print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))
                        #else:
                            #print(group['GroupId'] + ": Already exists " + range + ":" + str(permission['ToPort']))
        #print("----------- Revoking ----------")
        #print(to_revoke_G1)
        #print(to_revoke_G2)
        if (len(to_revoke_G1) > 0):
            removed += revoke_permissions(client, group, permission, to_revoke_G1, Type)

        if (len(to_revoke_G2) > 0):
            removed += revoke_permissions(client, group2, permission, to_revoke_G2, Type)
        old_prefixes_G1 = []
        old_prefixes_G2 = []
        if len(group['IpPermissionsEgress']) > 0:
            for permission in group['IpPermissionsEgress']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            old_prefixes_G1.append(cidr)
            SG_Count_G1 = len(old_prefixes_G1)
            #print ("SG_Count_G1:" + str(SG_Count_G1))

        if len(group2['IpPermissionsEgress']) > 0:
            for permission in group2['IpPermissionsEgress']:
                if permission['IpProtocol'] != '-1':
                    if permission['FromPort'] <= port and permission['ToPort'] >= port :
                        for range in permission['IpRanges']:
                            cidr = range['CidrIp']
                            old_prefixes_G2.append(cidr)
            SG_Count_G2 = len(old_prefixes_G2)
            #print ("SG_Count_G2:" + str(SG_Count_G2))

    #print("----------- Adding ----------")
    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    if (len(to_add_G1) > 0):
                        Available_G1 = MaxLimit - len(old_prefixes_G1)
                        Available_G2 = MaxLimit - len(old_prefixes_G2)
                        if (len(to_add_G1) <= Available_G1 and SG_ToAdd_G2 == 0):
                            #print("K1")
                            added += add_permissions_AWSServices(client, group, permission, to_add_G1, Type, group2)
                        elif (len(to_add_G1) <= Available_G2 and Available_G1 == 0):
                            #print("K2")
                            added += add_permissions_AWSServices(client, group2, permission, to_add_G1, Type, group2)
                        else:
                            to_add_G2 = to_add_G1[Available_G1:len(to_add_G1)]
                            del to_add_G1[Available_G1:len(to_add_G1)]
                            #print (len(to_add_G1))
                            #print (len(to_add_G2))
                            #print("K3")
                            added += add_permissions_AWSServices(client, group, permission, to_add_G1, Type, group2)
                            added += add_permissions_AWSServices(client, group2, permission, to_add_G2, Type, group2)

    #print (group['GroupId'] + ": Count " + str(len(new_ranges)) + ", Added " + str(added) + ", Revoked " + str(removed))
    print (group['GroupId'] + ": Count in JSON " + str(len(new_ranges)) + ", Actual Count " + str(len(new_ranges_Dup)) + ", Duplicate Count " + str(len(new_ranges) - len(new_ranges_Dup)) + ", Added " + str(added) + ", Revoked " + str(removed))

    return (added > 0 or removed > 0)

def update_security_group_for_proxy(client, group, port, Desc):
    added = 0
    removed = 0
    to_add = list()
    found = 0
    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] == '-1':
                found = 1
                print('Already All Traffic available for All ports')
                break

        if   found == 0:
            for permission in group['IpPermissionsEgress']:
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    range = permission['IpRanges']
                    if range.count('0.0.0.0/0') == 0:
                        found = 1
                        print('Already All Traffic available for ' + str(port) + ' port')
                        break

    if found == 0:
        to_add.append({ 'CidrIp': "0.0.0.0/0", 'Description':Desc })
        permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions_egress(client, group, permission, to_add)

    return (added > 0 or removed > 0)

def remove_security_group_for_proxy(client, group, port, Desc):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['IpProtocol'] == '-1':
                to_remove = list()
                to_remove.append({ 'CidrIp': "0.0.0.0/0" })
                removed += revoke_permissions_ingress_all(client, group, permission, to_remove)
                #print('Removed All Traffic for All ports')
                break
    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['IpProtocol'] != '-1':
                if permission['FromPort'] <= port and permission['ToPort'] >= port :
                    for range in permission['IpRanges']:
                        cidr = range['CidrIp']
                        if cidr == "0.0.0.0/0":
                            to_remove = list()
                            to_remove.append({ 'CidrIp': "0.0.0.0/0" })
                            removed += revoke_permissions_ingress(client, group, permission, to_remove)
                            print('Removed All Traffic for ' + str(port) + ' port')
                            break

    if len(group['IpPermissionsEgress']) > 0:
        for permission in group['IpPermissionsEgress']:
            if permission['IpProtocol'] == '-1':
                to_remove = list()
                to_remove.append({ 'CidrIp': "0.0.0.0/0" })
                removed += revoke_permissions_egress_all(client, group, permission, to_remove)
                print('Removed All Traffic for All ports')
                break

    return (added > 0 or removed > 0)

def revoke_permissions(client, group, permission, to_revoke, Type):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        if Type == "INGRESS":
            client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])
        elif Type == "EGRESS":
            client.revoke_security_group_egress(GroupId=group['GroupId'], IpPermissions=[revoke_params])
    return len(to_revoke)

def add_permissions(client, group, permission, to_add, Type, group2):
    found = 0
    add_params = {}
    to_add2 = []

    if SG_Max_Limit == -1:
        return 0

    if len(to_add) > 0:
        print (len(to_add))

        if len(to_add) > int(SG_Max_Limit):
            found = 1
            to_add2 = to_add[int(SG_Max_Limit):len(to_add)]
            del to_add[int(SG_Max_Limit):len(to_add)]
            print (len(to_add))
            print (len(to_add2))
            #print (to_add)
            #print (to_add2)
            add_params = {
                'ToPort': permission['ToPort'],
                'FromPort': permission['FromPort'],
                'IpRanges': to_add,
                'IpProtocol': permission['IpProtocol']
                }
            if Type == "INGRESS":
                client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])
            elif Type == "EGRESS":
                client.authorize_security_group_egress(GroupId=group['GroupId'], IpPermissions=[add_params])

            if found == 1:
                add_params2 = {
                    'ToPort': permission['ToPort'],
                    'FromPort': permission['FromPort'],
                    'IpRanges': to_add2,
                    'IpProtocol': permission['IpProtocol']
                    }
                if Type == "INGRESS":
                    client.authorize_security_group_ingress(GroupId=SG_AWS_Services_2_ID, IpPermissions=[add_params2])
                elif Type == "EGRESS":
                    client.authorize_security_group_egress(GroupId=SG_AWS_Services_2_ID, IpPermissions=[add_params2])
        return len(to_add) + len(to_add2)

def add_permissions_AWSServices(client, group, permission, to_add, Type, group2):
    add_params = {
        'ToPort': permission['ToPort'],
        'FromPort': permission['FromPort'],
        'IpRanges': to_add,
        'IpProtocol': permission['IpProtocol']
        }
    if Type == "INGRESS":
        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])
    elif Type == "EGRESS":
        client.authorize_security_group_egress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def add_permissions_egress(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_egress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def revoke_permissions_ingress(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def revoke_permissions_ingress_all(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'IpRanges': to_revoke,
            'IpProtocol': '-1'
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def revoke_permissions_egress(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_egress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def revoke_permissions_egress_all(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'IpRanges': to_revoke,
            'IpProtocol': '-1'
        }

        client.revoke_security_group_egress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def get_security_groups_for_update(client, groupids):
    #print("Inside get_security_groups_for_update")
    filters = list();
    response = client.describe_security_groups(GroupIds=[groupids])
    return response['SecurityGroups']
