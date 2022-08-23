import boto3
s3 = boto3.client('s3')

bucket = input("Enter your Bucket Name: ")
key = input("Enter your desired filename/key for this upload: ")
timer = input("Enter time in seconds when this URL will expire: ")

print(" Generating pre-signed url...")

print(s3.generate_presigned_url('put_object', Params={
      'Bucket': bucket, 'Key': key}, ExpiresIn=timer, HttpMethod='PUT'))
''' to send the file do a
curl -T test.txt https://presignedURL
'''
