import boto3
import time
import logging
import json
import os

dynamodb = boto3.client('dynamodb', region_name=os.environ['Region'])

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info('Event received: %s', event)
    
    try:
        if 'body' in event:
            body = json.loads(event['body'])
        else:
            body = event
        
        token = body.get('token')
        user_id = body.get('userId')
        
        if not token:
            raise KeyError('token')

        response = dynamodb.get_item(
            TableName=os.environ['DBName'],
            Key={
                'token': {'S': token},
                'userId': {'S': user_id}
            }
        )
        
        item = response.get('Item')
        logger.info('DynamoDB response: %s', response)
        
        if not item:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Invalid token'})
            }
        
        expiration_time = int(item['expirationTime']['N'])
        if time.time() > expiration_time:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Token has expired'})
            }

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Token is valid'})
        }
    
    except Exception as e:
        logger.error(f'Error validating token: {e}')
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Internal server error'})
        }
