from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from pymongo import MongoClient
from jose import JWTError, jwt
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# MongoDB setup
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

client = MongoClient(MONGODB_URI)
db = client[DATABASE_NAME]
users_collection = db["users"]
bank_accounts_collection = db["bank_accounts"]

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Create router
router = APIRouter(prefix="/api", tags=["bank-accounts"])


# Pydantic models
class BankAccountCreate(BaseModel):
    account_number: str
    cbn_bankcode: str
    account_name: str
    bank_name: Optional[str] = None  # Made optional


class BankAccountResponse(BaseModel):
    id: str
    user_id: str
    account_number: str
    cbn_bankcode: str
    account_name: str
    bank_name: str
    is_primary: bool
    created_at: datetime
    updated_at: datetime


class TokenData(BaseModel):
    email: Optional[str] = None


# Helper functions
def get_user_by_email(email: str):
    """Get user from database by email"""
    return users_collection.find_one({"email": email})


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current authenticated user from JWT token"""
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
@router.post("/save-bank-account", status_code=status.HTTP_201_CREATED)
async def save_bank_account(
    bank_data: BankAccountCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Save a bank account for the authenticated user.
    A user can only have ONE bank account. If they already have one, it will be replaced.
    
    Args:
        bank_data: BankAccountCreate containing account details
        current_user: Current authenticated user from JWT token
    
    Returns:
        Success message and saved bank account data
    """
    try:
        user_id = str(current_user["_id"])
        
        # Check if user already has a bank account
        existing_account = bank_accounts_collection.find_one({"user_id": user_id})
        
        if existing_account:
            # User can only have one account, so delete the existing one
            bank_accounts_collection.delete_one({"user_id": user_id})
        
        # Use provided bank_name or default to "Bank" if not provided
        bank_name = bank_data.bank_name if bank_data.bank_name else "Bank"
        
        # Prepare bank account document - always primary since user can only have one
        bank_account_doc = {
            "user_id": user_id,
            "account_number": bank_data.account_number,
            "cbn_bankcode": bank_data.cbn_bankcode,
            "account_name": bank_data.account_name,
            "bank_name": bank_name,
            "is_primary": True,  # Always primary since only one account allowed
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        # Insert into database
        result = bank_accounts_collection.insert_one(bank_account_doc)
        
        if not result.inserted_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save bank account"
            )
        
        # Get the inserted document
        saved_account = bank_accounts_collection.find_one({"_id": result.inserted_id})
        saved_account["_id"] = str(saved_account["_id"])
        
        return {
            "status": "success",
            "message": "Bank account linked successfully",
            "data": {
                "id": saved_account["_id"],
                "user_id": saved_account["user_id"],
                "account_number": saved_account["account_number"],
                "cbn_bankcode": saved_account["cbn_bankcode"],
                "account_name": saved_account["account_name"],
                "bank_name": saved_account["bank_name"],
                "is_primary": saved_account["is_primary"],
                "created_at": saved_account["created_at"],
                "updated_at": saved_account["updated_at"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving bank account: {str(e)}"
        )


@router.get("/bank-accounts")
async def get_user_bank_accounts(
    current_user: dict = Depends(get_current_user)
):
    """
    Get all bank accounts for the authenticated user.
    
    Args:
        current_user: Current authenticated user from JWT token
    
    Returns:
        List of user's bank accounts
    """
    try:
        user_id = str(current_user["_id"])
        
        # Get all bank accounts for this user
        accounts = list(bank_accounts_collection.find({"user_id": user_id}).sort("created_at", -1))
        
        # Convert ObjectId to string for JSON serialization
        for account in accounts:
            account["_id"] = str(account["_id"])
        
        return {
            "status": "success",
            "message": "Bank accounts retrieved successfully",
            "data": accounts,
            "count": len(accounts)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving bank accounts: {str(e)}"
        )


@router.get("/bank-accounts/primary")
async def get_primary_bank_account(
    current_user: dict = Depends(get_current_user)
):
    """
    Get the primary bank account for the authenticated user.
    
    Args:
        current_user: Current authenticated user from JWT token
    
    Returns:
        Primary bank account or None
    """
    try:
        user_id = str(current_user["_id"])
        
        # Get primary bank account
        account = bank_accounts_collection.find_one({
            "user_id": user_id,
            "is_primary": True
        })
        
        if not account:
            return {
                "status": "success",
                "message": "No primary bank account found",
                "data": None
            }
        
        # Convert ObjectId to string
        account["_id"] = str(account["_id"])
        
        return {
            "status": "success",
            "message": "Primary bank account retrieved successfully",
            "data": account
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving primary bank account: {str(e)}"
        )


@router.put("/bank-accounts/{account_id}/set-primary")
async def set_primary_bank_account(
    account_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Set a specific bank account as primary for the authenticated user.
    
    Args:
        account_id: ID of the bank account to set as primary
        current_user: Current authenticated user from JWT token
    
    Returns:
        Success message
    """
    try:
        from bson import ObjectId
        
        user_id = str(current_user["_id"])
        
        # Verify the account belongs to the user
        account = bank_accounts_collection.find_one({
            "_id": ObjectId(account_id),
            "user_id": user_id
        })
        
        if not account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bank account not found"
            )
        
        # Remove primary flag from all user's accounts
        bank_accounts_collection.update_many(
            {"user_id": user_id},
            {"$set": {"is_primary": False, "updated_at": datetime.utcnow()}}
        )
        
        # Set this account as primary
        bank_accounts_collection.update_one(
            {"_id": ObjectId(account_id)},
            {"$set": {"is_primary": True, "updated_at": datetime.utcnow()}}
        )
        
        return {
            "status": "success",
            "message": "Primary bank account updated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error setting primary bank account: {str(e)}"
        )


@router.delete("/bank-accounts/{account_id}")
async def delete_bank_account(
    account_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a bank account for the authenticated user.
    
    Args:
        account_id: ID of the bank account to delete
        current_user: Current authenticated user from JWT token
    
    Returns:
        Success message
    """
    try:
        from bson import ObjectId
        
        user_id = str(current_user["_id"])
        
        # Verify the account belongs to the user
        account = bank_accounts_collection.find_one({
            "_id": ObjectId(account_id),
            "user_id": user_id
        })
        
        if not account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bank account not found"
            )
        
        # Check if this is the primary account
        was_primary = account.get("is_primary", False)
        
        # Delete the account
        result = bank_accounts_collection.delete_one({
            "_id": ObjectId(account_id),
            "user_id": user_id
        })
        
        if result.deleted_count == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete bank account"
            )
        
        # If deleted account was primary, set another account as primary
        if was_primary:
            remaining_account = bank_accounts_collection.find_one({"user_id": user_id})
            if remaining_account:
                bank_accounts_collection.update_one(
                    {"_id": remaining_account["_id"]},
                    {"$set": {"is_primary": True, "updated_at": datetime.utcnow()}}
                )
        
        return {
            "status": "success",
            "message": "Bank account deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting bank account: {str(e)}"
        )


# Example usage
if __name__ == "__main__":
    print("Bank Accounts API Routes:")
    print("POST   /api/save-bank-account - Save a new bank account")
    print("GET    /api/bank-accounts - Get all user's bank accounts")
    print("GET    /api/bank-accounts/primary - Get primary bank account")
    print("PUT    /api/bank-accounts/{account_id}/set-primary - Set account as primary")
    print("DELETE /api/bank-accounts/{account_id} - Delete a bank account")