import hashlib
import os
from dotenv import load_dotenv
import base64
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import http.client
import json
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Load environment variables
load_dotenv()

# Get secrets from environment
SECRET_KEY = os.getenv("secretKey")
API_KEY = os.getenv("api_key")
ONEPIPE_URL = os.getenv("onepipe_url")

# Create router
router = APIRouter(prefix="/api", tags=["invoice"])


def MD5Hash(request_ref: str, client_secret: str) -> str:
    """
    Generate MD5 hash from request_ref and client_secret.
    
    Args:
        request_ref (str): The request reference string
        client_secret (str): The client secret key (required)
    
    Returns:
        str: MD5 hash in hexadecimal format
    """
    # Combine request_ref and client_secret with semicolon (concatenation)
    combined_string = f"{request_ref};{client_secret}"
    
    # Generate MD5 hash
    md5_hash = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
    
    return md5_hash


def TripleDES_encrypt(account_number: str, cbn_bankcode: str, secret_key: str) -> str:
    try:
        plain_text = f"{account_number};{cbn_bankcode}"
        
        buffered_key = secret_key.encode('utf-16le')
        md5_hash = hashlib.md5(buffered_key).digest()
        
        new_key = md5_hash + md5_hash[:8]
        
        iv = b'\x00' * 8
        
        cipher = DES3.new(new_key, DES3.MODE_CBC, iv)
        
        plain_text_bytes = plain_text.encode('utf-16le')  # Change to utf-16le
        
        padded_text = pad(plain_text_bytes, DES3.block_size)
        
        encrypted_data = cipher.encrypt(padded_text)
        
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    except Exception as e:
        print(f"TripleDES_encrypt error: {str(e)}")
        raise

def TripleDES_decrypt(encrypted_text: str, secret_key: str) -> str:
    try:
        buffered_key = secret_key.encode('utf-16le')
        md5_hash = hashlib.md5(buffered_key).digest()
        
        new_key = md5_hash + md5_hash[:8]
        
        iv = b'\x00' * 8
        
        cipher = DES3.new(new_key, DES3.MODE_CBC, iv)
        
        encrypted_data = base64.b64decode(encrypted_text)
        
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        decrypted_text = unpad(decrypted_padded, DES3.block_size).decode('utf-16le')  # Change to utf-16le
        
        return decrypted_text
        
    except Exception as e:
        print(f"TripleDES_decrypt error: {str(e)}")
        raise


# Pydantic models for request validation
class Customer(BaseModel):
    customer_ref: str
    firstname: str
    surname: str
    email: EmailStr
    mobile_no: str


class Meta(BaseModel):
    type: str = "instalment"
    down_payment: int
    repeat_frequency: str
    repeat_start_date: str
    number_of_payments: int
    biller_code: str  = "000734"


class Transaction(BaseModel):
    mock_mode: str = "Inspect"
    transaction_ref: str
    transaction_desc: str
    transaction_ref_parent: None
    amount: int
    customer: Customer
    meta: Meta
    details: Dict[str, Any] = {}


class Auth(BaseModel):
    type: str 
    secure: str
    auth_provider: str


class InvoiceRequest(BaseModel):
    request_ref: str
    request_type: str
    auth: Auth
    transaction: Transaction


class InvoicePayload(BaseModel):
    account_number: str
    cbn_bankcode: str
    request_ref: str
    request_type: str = "send invoice"
    auth_type: str = "bank.account"
    auth_provider: str = "PaywithAccount"
    transaction: Transaction


@router.post("/invoice")
async def send_invoice(payload: InvoicePayload):
    """
    Send invoice endpoint that encrypts account details and calls OnePipe API.
    
    Args:
        payload: InvoicePayload containing account details and transaction info
    
    Returns:
        Response from OnePipe API
    """
    try:
        # Encrypt account_number and cbn_bankcode using TripleDES
        try:
            encrypted_secure = TripleDES_encrypt(
                payload.account_number,
                payload.cbn_bankcode,
                SECRET_KEY
            )
            print(f"Encryption successful: {encrypted_secure[:50]}...")
        except Exception as enc_error:
            print(f"Encryption failed: {str(enc_error)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Encryption failed: {str(enc_error)}"
            )
        
        # Generate MD5 signature
        signature = MD5Hash(payload.request_ref, SECRET_KEY)
        
        # Build the request body for OnePipe API
        request_body = {
            "request_ref": payload.request_ref,
            "request_type": payload.request_type,
            "auth": {
                "type": payload.auth_type,
                "secure": encrypted_secure,
                "auth_provider": payload.auth_provider
            },
            "transaction": payload.transaction.model_dump()
        }
        
        # Convert request body to JSON string (compact, no extra formatting)
        json_payload = json.dumps(request_body)
        
        # Set up headers - Order matters: Authorization, Signature, Content-Type
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
                    "Authorization": f"Bearer {API_KEY[:10]}...",  # Masked for security
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


# Example usage
if __name__ == "__main__":
    # Test MD5Hash
    request_ref = input("Enter request_ref: ")
    md5_result = MD5Hash(request_ref, SECRET_KEY)
    print(f"MD5 Hash: {md5_result}")
    
    # Test TripleDES encryption
    account_number = input("Enter account_number: ")
    cbn_bankcode = input("Enter cbn_bankcode: ")
    encrypted = TripleDES_encrypt(account_number, cbn_bankcode, SECRET_KEY)
    print(f"Encrypted: {encrypted}")
    
    # Test TripleDES decryption
    decrypted = TripleDES_decrypt(encrypted, SECRET_KEY)
    print(f"Decrypted: {decrypted}")