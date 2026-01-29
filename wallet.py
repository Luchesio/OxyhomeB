from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
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
webhooks_collection = db["webhook"]

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Create router
router = APIRouter(prefix="/api", tags=["wallet"])


class TokenData:
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
        token_data = TokenData()
        token_data.email = email
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


# Routes
@router.get("/wallet/balance")
async def get_wallet_balance(current_user: dict = Depends(get_current_user)):
    """
    Get wallet balance for the authenticated user by summing up pwt_item_amount from webhooks.
    
    Args:
        current_user: Current authenticated user from JWT token
    
    Returns:
        Wallet balance and transaction summary
    """
    try:
        user_phone = current_user.get("phone_number")
        
        if not user_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User phone number not found"
            )
        
        # Query webhooks for this user (using customer_ref or mobile_no)
        # Assuming customer_ref or customer_mobile_no matches user's phone_number
        webhooks = list(webhooks_collection.find({
            "$or": [
                {"details.customer_ref": user_phone},
                {"details.customer_mobile_no": user_phone}
            ]
        }).sort("received_at", -1))
        
        # Calculate total balance from pwt_item_amount
        total_balance = 0
        successful_transactions = 0
        
        for webhook in webhooks:
            details = webhook.get("details", {})
            meta = details.get("meta", {})
            status_field = details.get("status", "").lower()
            
            # Only count successful transactions
            if "success" in status_field or "complete" in status_field:
                pwt_item_amount = meta.get("pwt_item_amount", 0)
                if pwt_item_amount:
                    total_balance += pwt_item_amount
                    successful_transactions += 1
        
        # Convert from kobo to naira (divide by 100)
        balance_in_naira = total_balance / 100
        
        return {
            "status": "success",
            "message": "Wallet balance retrieved successfully",
            "data": {
                "balance": balance_in_naira,
                "balance_kobo": total_balance,
                "currency": "NGN",
                "total_transactions": len(webhooks),
                "successful_transactions": successful_transactions,
                "last_updated": datetime.utcnow()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving wallet balance: {str(e)}"
        )


@router.get("/wallet/transactions")
async def get_wallet_transactions(current_user: dict = Depends(get_current_user)):
    """
    Get all wallet transactions for the authenticated user.
    
    Args:
        current_user: Current authenticated user from JWT token
    
    Returns:
        List of transactions with amounts and details
    """
    try:
        user_phone = current_user.get("phone_number")
        
        if not user_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User phone number not found"
            )
        
        # Query webhooks for this user
        webhooks = list(webhooks_collection.find({
            "$or": [
                {"details.customer_ref": user_phone},
                {"details.customer_mobile_no": user_phone}
            ]
        }).sort("received_at", -1))
        
        # Format transactions
        transactions = []
        for webhook in webhooks:
            details = webhook.get("details", {})
            meta = details.get("meta", {})
            
            pwt_item_amount = meta.get("pwt_item_amount", 0)
            amount_in_naira = pwt_item_amount / 100 if pwt_item_amount else 0
            
            transaction = {
                "id": str(webhook.get("_id")),
                "amount": amount_in_naira,
                "amount_kobo": pwt_item_amount,
                "currency": "NGN",
                "status": details.get("status", "Unknown"),
                "transaction_ref": details.get("transaction_ref", ""),
                "transaction_desc": details.get("transaction_desc", ""),
                "payment_option": meta.get("payment_option", ""),
                "note": meta.get("note", ""),
                "date": webhook.get("received_at"),
                "provider": details.get("provider", "")
            }
            
            transactions.append(transaction)
        
        return {
            "status": "success",
            "message": "Transactions retrieved successfully",
            "data": transactions,
            "count": len(transactions)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving transactions: {str(e)}"
        )


# Example usage
if __name__ == "__main__":
    print("Wallet API Routes:")
    print("GET    /api/wallet/balance - Get wallet balance")
    print("GET    /api/wallet/transactions - Get wallet transactions")