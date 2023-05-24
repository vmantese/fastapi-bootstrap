import os
import base64
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, Security, APIRouter
from fastapi.security import HTTPBasic, HTTPBearer, HTTPBasicCredentials
from mangum import Mangum
import boto3

app = FastAPI()
handler = Mangum(app)

# Set up DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('tickets')

# Set up authentication
def verify_user_credentials(credentials: HTTPBasicCredentials):
    if credentials.username in auth_users and credentials.password == auth_users[credentials.username]:
        return credentials.username
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid username or password')
    


def verify_user_token(security):
    #todo
    return True

# Set up authentication
auth_type = os.getenv('AUTH_TYPE', 'bearer')
if auth_type == 'basic':
    security = HTTPBasic()
    authenticate_user = verify_user_credentials
else:
    security = HTTPBearer()
    authenticate_user = verify_user_token

# Load auth users from environment variable
auth_users_json = os.getenv('AUTH_USERS', '')
try:
    auth_users = json.loads(base64.urlsafe_b64decode(auth_users_json + '===').decode('utf-8'))
except:
    auth_users = {}

# Define models
class TicketFilter:
    # Define fields for filter object
    pass

class Ticket:
    # Define fields for ticket object
    pass

class TicketUpdate:
    id: List[str]
    status: str

# Define API router
api_router = APIRouter(prefix='/api', dependencies=[Depends(authenticate_user)])

@api_router.get('/tickets')
async def get_tickets(filters: str = '', page_num: int = 0, page_size: int = 10, sort_column: str = '', sort_direction: str = 'ascending',sort_start_key: str = ''):
    # Decode and parse filter object
    filter_dict = json.loads(base64.urlsafe_b64decode(filters + '===').decode('utf-8'))
    
    #postprocess filter_dict

    #sort column postprocess

    # Query DynamoDB table with filter and pagination parameters
    response = table.query(
        IndexName=sort_column,
        KeyConditionExpression=filter_dict,
        Limit=page_size,
        ScanIndexForward=sort_direction == 'ascending',
        ExclusiveStartKey={'id': page_num * page_size} # you may have 
    )
    
    #local sort page results
    # Sort results if sort column is specified
    #if sort_column:
    #    response['Items'].sort(key=lambda x: x[sort_column], reverse=sort_direction == 'descending')
    
    # Return paginated results
    items = response['Items']

    #process items
    
    json_items = json.dumps(items)

    return json_items

@api_router.get('/tickets/{ticket_id}')
async def get_ticket(ticket_id: str):
    # Query DynamoDB table for ticket with specified ID
    response = table.get_item(Key={'id': ticket_id})
    
    # Return ticket if it exists, otherwise raise HTTPException
    if 'Item' in response:
        item = response['Item']
        # process item
        json_item = json.dumps(item)
        return json_item
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Ticket not found')

@api_router.put('/tickets/update-ticket-status')
async def update_ticket_status(ticket_update: TicketUpdate):
    # Update status of tickets with specified IDs
    for ticket_id in ticket_update.id:
        table.update_item(
            Key={'id': ticket_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': ticket_update.status}
        )
    
    # Return success message
    return {'message': 'Ticket status updated successfully'}

# Mount API router
app.include_router(api_router)