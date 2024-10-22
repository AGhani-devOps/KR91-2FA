import boto3
import random
import string
import time
import logging
import json
import os

dynamodb = boto3.client('dynamodb', region_name=os.environ['Region'])
sns = boto3.client('sns', region_name=os.environ['Region'])

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info('Event received: %s', event)
    
    try:
        if 'body' in event:
            body = json.loads(event['body'])
            user_id = body.get('userId')
            email = body.get('email')
        else:
            user_id = event.get('userId')
            email = event.get('email')
        
        if not user_id or not email:
            raise KeyError('userId or email')
    except KeyError as e:
        logger.error(f'Missing key in event: {e}')
        return {
            'statusCode': 400,
            'body': json.dumps({'message': f'Missing key: {e}'})
        }
    except json.JSONDecodeError as e:
        logger.error(f'Error parsing JSON: {e}')
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Invalid JSON format'})
        }
    
    token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    expiration_time = int(time.time()) + 300

    dynamodb.put_item(
        TableName=os.environ['DBName'],
        Item={
            'token': {'S': token},
            'userId': {'S': user_id},
            'expirationTime': {'N': str(expiration_time)}
        }
    )

    sns.publish(
        TargetArn='arn:aws:sns:us-east-1:390403884481:mytest',
        Message=f'Your verification token is {token}',
        Subject='Your Verification Token'
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Token sent successfully', 'token': token})
    }
