import os
import base64
import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBasic, HTTPBearer, HTTPBasicCredentials
from mangum import Mangum
import boto3

app = FastAPI()
handler = Mangum(app)

# Set up DynamoDB client
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('tickets')

# Set up authentication
security = HTTPBearer() if os.getenv('AUTH_TYPE', 'bearer') == 'bearer' else HTTPBasic()
auth_users = {
    'user1': 'password1',
    'user2': 'password2'
}

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

# Define routes
@app.get('/api/tickets')
async def get_tickets(filters: str = '', page_num: int = 0, page_size: int = 10, sort_column: str = '', sort_direction: str = '', auth: str = Security(security)):
    # Decode and parse filter object
    filter_dict = json.loads(base64.urlsafe_b64decode(filters + '===').decode('utf-8'))
    
    # Query DynamoDB table with filter and pagination parameters
    response = table.query(
        IndexName=sort_column,
        KeyConditionExpression=filter_dict,
        Limit=page_size,
        ExclusiveStartKey={'id': page_num * page_size}
    )
    
    # Sort results if sort column is specified
    if sort_column:
        response['Items'].sort(key=lambda x: x[sort_column], reverse=sort_direction == 'desc')
    
    # Return paginated results
    return response['Items']

@app.get('/api/tickets/{ticket_id}')
async def get_ticket(ticket_id: str, auth: str = Security(security)):
    # Query DynamoDB table for ticket with specified ID
    response = table.get_item(Key={'id': ticket_id})
    
    # Return ticket if it exists, otherwise raise HTTPException
    if 'Item' in response:
        return response['Item']
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Ticket not found')

@app.put('/api/tickets/update-ticket-status')
async def update_ticket_status(ticket_update: TicketUpdate, auth: str = Security(security)):
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