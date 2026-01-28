from fastapi import APIRouter, HTTPException, status, Depends, Form, Request, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import re
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import hashlib

load_dotenv()

# MongoDB setup
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
WEBHOOK_SECRET_KEY = os.getenv("secretKey")  # This is the secretKey for webhook signature
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 525600  # Default token expiration time

client = MongoClient(MONGODB_URI)
db = client[DATABASE_NAME]
users_collection = db["users"]
webhooks_collection = db["webhook"]

# Password hashing - Updated to handle bcrypt's 72-byte limitation
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__ident="2b")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Router
router = APIRouter(prefix="/auth", tags=["Authentication"])


# Pydantic models
class UserLogin(BaseModel):
    email: EmailStr
    password: str


class WebhookData(BaseModel):
    payment_date: Optional[str] = None
    invoice_number: Optional[str] = None
    account_number: Optional[str] = None
    provider: Optional[str] = None
    point_type: Optional[str] = None
    gender: Optional[str] = None
    dob: Optional[str] = None
    address_building_number: Optional[str] = None
    address_street: Optional[str] = None
    address_city: Optional[str] = None
    address_post_code: Optional[str] = None


class WebhookMeta(BaseModel):
    grb_status: Optional[str] = None
    pwt_item_description: Optional[str] = None
    pwt_item_code: Optional[str] = None
    pwt_item_amount: Optional[int] = None
    lock_account: Optional[bool] = None
    transaction_date: Optional[str] = None
    created_date: Optional[str] = None
    biller_id: Optional[str] = None
    biller_item_id: Optional[str] = None
    processing_method: Optional[str] = None
    page_id: Optional[int] = None
    currency: Optional[str] = None
    gender: Optional[str] = None
    dob: Optional[str] = None
    address_building_number: Optional[str] = None
    address_street: Optional[str] = None
    address_city: Optional[str] = None
    address_post_code: Optional[str] = None
    provider_auth_token: Optional[str] = None
    payment_option: Optional[str] = None
    fulfilment_delivery: Optional[str] = None
    note: Optional[str] = None


class WebhookDetails(BaseModel):
    amount: Optional[str] = None
    transaction_type: Optional[str] = None
    transaction_ref: Optional[str] = None
    transaction_desc: Optional[str] = None
    status: Optional[str] = None
    provider: Optional[str] = None
    customer_ref: Optional[str] = None
    customer_email: Optional[str] = None
    customer_firstname: Optional[str] = None
    customer_surname: Optional[str] = None
    customer_mobile_no: Optional[str] = None
    data: Optional[WebhookData] = None
    meta: Optional[WebhookMeta] = None


class WebhookAppInfo(BaseModel):
    app_code: Optional[str] = None


class WebhookPayload(BaseModel):
    request_ref: str
    request_type: Optional[str] = None
    requester: Optional[str] = None
    mock_mode: Optional[str] = None
    details: Optional[WebhookDetails] = None
    app_info: Optional[WebhookAppInfo] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class UserResponse(BaseModel):
    email: str
    first_name: str
    last_name: str
    phone_number: str
    created_at: datetime


class UserUpdateRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


# Helper functions
def truncate_password(password: str) -> bytes:
    """Truncate password to 72 bytes for bcrypt compatibility"""
    password_bytes = password.encode('utf-8')
    return password_bytes[:72]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    truncated = truncate_password(plain_password)
    return pwd_context.verify(truncated, hashed_password)


def get_password_hash(password: str) -> str:
    truncated = truncate_password(password)
    return pwd_context.hash(truncated)


def convert_phone_to_international(phone_number: str) -> str:
    """
    Convert Nigerian phone number from 09056035245 to 2349056035245
    Removes leading 0 and adds 234 country code
    """
    # Remove any whitespace
    phone_number = phone_number.strip()
    
    # If it starts with 0, remove it and add 234
    if phone_number.startswith('0'):
        return '234' + phone_number[1:]
    
    # If it already starts with 234, return as is
    if phone_number.startswith('234'):
        return phone_number
    
    # Otherwise, just add 234
    return '234' + phone_number


def verify_webhook_signature(request_ref: str, signature: str, secret_key: str) -> bool:
    """
    Verify webhook signature using MD5 hash
    
    Args:
        request_ref: The request reference from webhook payload
        signature: The signature from webhook header
        secret_key: The secret key from environment
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Generate expected signature: MD5Hash(request_ref;secretKey)
    combined_string = f"{request_ref};{secret_key}"
    expected_signature = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
    
    return signature.lower() == expected_signature.lower()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str):
    return users_collection.find_one({"email": email})


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


# Routes


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    email: EmailStr = Form(...),
    password: str = Form(..., min_length=8),
    confirm_password: str = Form(...),
    phone_number: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...)
):
    # Validate that passwords match
    if password != confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match"
        )
    
    # Validate phone number (Nigerian format)
    pattern = r'^0[7-9][0-1]\d{8}$'
    if not re.match(pattern, phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number must be in format: 09056035245 (11 digits starting with 070-091)"
        )

    # Convert phone number to international format (234...)
    international_phone = convert_phone_to_international(phone_number)

    existing_user = get_user_by_email(email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if international phone number already exists
    existing_phone = users_collection.find_one({"phone_number": international_phone})
    if existing_phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered"
        )

    user_dict = {
        "email": email,
        "password": get_password_hash(password),
        "phone_number": international_phone,  # Store in international format
        "first_name": first_name,
        "last_name": last_name,
        "created_at": datetime.utcnow()
    }

    result = users_collection.insert_one(user_dict)
    if not result.inserted_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )

    created_user = users_collection.find_one({"_id": result.inserted_id})
    return UserResponse(
        email=created_user["email"],
        first_name=created_user["first_name"],
        last_name=created_user["last_name"],
        phone_number=created_user["phone_number"],
        created_at=created_user["created_at"]
    )


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user["email"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "first_name": current_user.get("first_name"),
        "last_name": current_user.get("last_name"),
        "email": current_user.get("email"),
        "phone_number": current_user.get("phone_number"),
        "created_at": current_user.get("created_at"),
        "id": str(current_user.get("_id"))
    }


@router.put("/me", response_model=UserResponse)
async def update_user_profile(
    update_data: UserUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Update current user's profile information"""
    
    # Check if email is being changed and if it's already taken by another user
    if update_data.email != current_user["email"]:
        existing_user = get_user_by_email(update_data.email)
        if existing_user and str(existing_user["_id"]) != str(current_user["_id"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
    
    # Convert phone number to international format
    international_phone = convert_phone_to_international(update_data.phone_number)
    
    # Check if phone number is being changed and if it's already taken by another user
    if international_phone != current_user["phone_number"]:
        existing_phone = users_collection.find_one({"phone_number": international_phone})
        if existing_phone and str(existing_phone["_id"]) != str(current_user["_id"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered"
            )
    
    # Update user data
    update_dict = {
        "first_name": update_data.first_name,
        "last_name": update_data.last_name,
        "email": update_data.email,
        "phone_number": international_phone
    }
    
    result = users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": update_dict}
    )
    
    if result.modified_count == 0 and result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )
    
    # Fetch updated user
    updated_user = users_collection.find_one({"_id": current_user["_id"]})
    
    return UserResponse(
        email=updated_user["email"],
        first_name=updated_user["first_name"],
        last_name=updated_user["last_name"],
        phone_number=updated_user["phone_number"],
        created_at=updated_user["created_at"]
    )


@router.post("/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user)
):
    """Change user's password"""
    
    # Verify current password
    if not verify_password(password_data.current_password, current_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Check if new passwords match
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New passwords do not match"
        )
    
    # Validate new password length
    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long"
        )
    
    # Check if new password is different from current password
    if password_data.current_password == password_data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password"
        )
    
    # Hash and update password
    new_password_hash = get_password_hash(password_data.new_password)
    
    result = users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"password": new_password_hash}}
    )
    
    if result.modified_count == 0 and result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )
    
    return {
        "status": "success",
        "message": "Password updated successfully"
    }


@router.post("/webhook")
async def receive_webhook(
    payload: WebhookPayload,
    signature: str = Header(..., alias="Signature")
):
    """
    Receive and store webhook data with signature verification.
    
    The signature should be: MD5Hash(request_ref;secretKey)
    """
    try:
        # Verify webhook signature
        if not verify_webhook_signature(payload.request_ref, signature, WEBHOOK_SECRET_KEY):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature"
            )
        
        # Convert payload to dict for storage
        webhook_data = {
            "request_ref": payload.request_ref,
            "request_type": payload.request_type,
            "requester": payload.requester,
            "mock_mode": payload.mock_mode,
            "details": payload.details.model_dump() if payload.details else None,
            "app_info": payload.app_info.model_dump() if payload.app_info else None,
            "received_at": datetime.utcnow(),
            "signature": signature
        }
        
        # Store webhook in database
        result = webhooks_collection.insert_one(webhook_data)
        
        if not result.inserted_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store webhook data"
            )
        
        # Return the expected response format
        return {
            "status": "Successful",
            "message": "Ticket issued",
            "data": {}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing webhook: {str(e)}"
        )


@router.get("/webhooks")
async def get_all_webhooks(current_user: dict = Depends(get_current_user)):
    """Retrieve all webhook entries from database (requires authentication)"""
    try:
        webhooks = list(webhooks_collection.find({}).sort("received_at", -1))
        
        # Convert ObjectId to string for JSON serialization
        for webhook in webhooks:
            webhook["_id"] = str(webhook["_id"])
        
        return {
            "status": "success",
            "webhooks": webhooks,
            "count": len(webhooks)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving webhooks: {str(e)}"
        )