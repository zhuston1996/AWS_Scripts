import boto3, json

def lambda_handler(event, context):
    aws_account_id='586672212047'
    namespace='default'
    bucket = event['Records'][0]['s3']['bucket']['name']
    file = event['Records'][0]['s3']['object']['key']
    json_content = s3ReadObject(bucket, file)
    errors = addUsertoQuickSightGroup(json_content, aws_account_id, namespace)
    if len(errors) < 1:
        errors.append("No Errors")
    print(f'Errors: {errors}')
    return {
        'statusCode': 200,
        'body': json.dumps({'Errors': errors})
    }
    
def s3ReadObject(bucket_name, file_name):
    s3 = boto3.resource('s3')
    content_object = s3.Object(bucket_name, file_name)
    file_content = content_object.get()['Body'].read().decode('utf-8')
    json_content = json.loads(file_content)
    return(json_content)
    
def addUsertoQuickSightGroup(userfile, aws_account_id, namespace):
    quicksight = boto3.client('quicksight', region_name='us-east-1')
    errors = []
    for user in userfile:
        try:
            response = quicksight.create_group_membership(
                MemberName=user['member-name'],
                GroupName=user['group'],
                AwsAccountId=aws_account_id,
                Namespace=namespace
                )
        except Exception as e:
            errors.append(str(e))
    return(errors)