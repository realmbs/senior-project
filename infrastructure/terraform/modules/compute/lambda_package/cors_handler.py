import json

def lambda_handler(event, context):
    """Dedicated CORS handler for OPTIONS requests"""

    # CORS headers
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Max-Age': '3600'
    }

    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({'message': 'CORS preflight OK'})
    }