import hashlib
import os
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import http.client
import json

# Load environment variables
load_dotenv()

# Get secrets from environment
SECRET_KEY = os.getenv("secretKey")
API_KEY = os.getenv("api_key")
ONEPIPE_URL = os.getenv("onepipe_url")

# Create router
router = APIRouter(prefix="/api", tags=["mandate"])


def MD5Hash(request_ref: str, client_secret: str) -> str:
    """
    Generate MD5 hash from request_ref and client_secret.
    
    Args:
        request_ref (str): The request reference string
        client_secret (str): The client secret key
    
    Returns:
        str: MD5 hash in hexadecimal format
    """
    combined_string = f"{request_ref};{client_secret}"
    md5_hash = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
    return md5_hash


# Pydantic models for request validation
class Customer(BaseModel):
    customer_ref: str
    firstname: str
    surname: str
    email: EmailStr
    mobile_no: str


class Meta(BaseModel):
    biller_code: str = "000734"


class Transaction(BaseModel):
    mock_mode: str = "Live"
    transaction_ref: str
    transaction_desc: str = "Check active mandates"
    transaction_ref_parent: None = None
    amount: int = 0
    customer: Customer
    meta: Meta
    details: Dict[str, Any] = {}


class MandateRequest(BaseModel):
    request_ref: str
    request_type: str = "Get Accounts Max"
    transaction: Transaction


@router.post("/mandate")
async def get_mandates(payload: MandateRequest):
    """
    Get user mandates endpoint that calls OnePipe API.
    
    Args:
        payload: MandateRequest containing transaction info and customer details
    
    Returns:
        Response from OnePipe API with active mandates
    """
    try:
        # Generate MD5 signature
        signature = MD5Hash(payload.request_ref, SECRET_KEY)
        
        # Build the request body for OnePipe API
        request_body = {
            "request_ref": payload.request_ref,
            "request_type": payload.request_type,
            "auth": {
                "type": None,
                "secure": None,
                "auth_provider": "PaywithAccount"
            },
            "transaction": payload.transaction.model_dump()
        }
        
        # Convert request body to JSON string
        json_payload = json.dumps(request_body)
        
        # Set up headers
        headers = {
            'Authorization': f'Bearer {API_KEY}',
            'Signature': signature,
            'Content-Type': 'application/json'
        }
        
        # Create HTTPS connection to OnePipe API
        conn = http.client.HTTPSConnection("api.dev.onepipe.io")
        
        # Make POST request
        conn.request("POST", "/v2/transact", json_payload, headers)
        
        # Get response
        res = conn.getresponse()
        data = res.read()
        
        # Decode response
        response_text = data.decode("utf-8")
        
        # Try to parse as JSON
        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            response_json = {"raw_response": response_text}
        
        # Close connection
        conn.close()
        
        # Return the response from OnePipe
        return {
            "status_code": res.status,
            "response": response_json,
            "request_sent": {
                "url": ONEPIPE_URL,
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {API_KEY[:10]}...",
                    "Signature": signature
                },
                "body": request_body
            }
        }
            
    except HTTPException:
        raise
    except http.client.HTTPException as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error calling OnePipe API: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )