from fastapi import APIRouter, HTTPException, status, Depends, Form
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

load_dotenv()

# MongoDB setup
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 525600  # Default token expiration time

client = MongoClient(MONGODB_URI)
db = client[DATABASE_NAME]
users_collection = db["users"]
webhooks_collection = db["webhook"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Router
router = APIRouter(prefix="/auth", tags=["Authentication"])


# Pydantic models (removed UserSignUp since we're using Form fields now)
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class WebhookPayload(BaseModel):
    # Define the expected webhook payload structure
    # Adjust fields based on what you expect to receive
    event: str
    data: dict
    timestamp: Optional[datetime] = None

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class UserResponse(BaseModel):
    email: str
    full_name: str
    phone_number: str
    created_at: datetime


# Helper functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


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
    phone_number: str = Form(...),
    full_name: str = Form(...)
):
    # Validate phone number
    pattern = r'^0[7-9][0-1]\d{8}$'
    if not re.match(pattern, phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number must be in format: 09056035245 (11 digits starting with 070-091)"
        )

    # No need for additional password validation as min_length handles it

    existing_user = get_user_by_email(email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    existing_phone = users_collection.find_one({"phone_number": phone_number})
    if existing_phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered"
        )

    user_dict = {
        "email": email,
        "password": get_password_hash(password),
        "phone_number": phone_number,
        "full_name": full_name,
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
        full_name=created_user["full_name"],
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


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        email=current_user["email"],
        full_name=current_user["full_name"],
        phone_number=current_user["phone_number"],
        created_at=current_user["created_at"]
    )

@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "full_name": current_user.get("full_name"),
        "email": current_user.get("email"),
        "phone_number": current_user.get("phone_number"),
        "created_at": current_user.get("created_at"),
        "id": str(current_user.get("_id"))
    }


@router.post("/webhook")
async def receive_webhook(payload: WebhookPayload):
    """Receive and store webhook data"""
    try:
        webhook_data = {
            "event": payload.event,
            "data": payload.data,
            "timestamp": payload.timestamp or datetime.utcnow(),
            "received_at": datetime.utcnow()
        }
        
        result = webhooks_collection.insert_one(webhook_data)
        
        if not result.inserted_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store webhook data"
            )
        
        return {
            "status": "success",
            "message": "Webhook received and stored",
            "id": str(result.inserted_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing webhook: {str(e)}"
        )


@router.get("/webhooks")
async def get_all_webhooks(current_user: dict = Depends(get_current_user)):
    """Retrieve all webhook entries from database (requires authentication)"""
    webhooks = list(webhooks_collection.find({}).sort("received_at", -1))
    
    # Convert ObjectId to string for JSON serialization
    for webhook in webhooks:
        webhook["_id"] = str(webhook["_id"])
    
    return {"webhooks": webhooks, "count": len(webhooks)}