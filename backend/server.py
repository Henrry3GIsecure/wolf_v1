from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Request, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import json
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from pathlib import Path
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uuid
import hashlib
import secrets
import re
import httpx
from passlib.context import CryptContext
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(
    title="WOLF - Cybersecurity Threat Intelligence",
    description="Sistema de inteligencia de amenazas de ciberseguridad",
    version="1.0.0"
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# JWT settings
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"

# Language detection API
IPGEOLOCATION_API_KEY = os.environ.get('IPGEOLOCATION_API_KEY')

# Models
class UserCreate(BaseModel):
    email: str
    password: str
    pin: str
    phone: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) != 24:
            raise ValueError('Password must be exactly 24 characters')
        return v
    
    @validator('pin')
    def validate_pin(cls, v):
        if len(v) != 5 or not v.isdigit():
            raise ValueError('PIN must be exactly 5 digits')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password_hash: str
    pin_hash: str
    phone: Optional[str] = None
    is_admin: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    last_login: Optional[datetime] = None

class UserLogin(BaseModel):
    email: str
    password: str

class PasswordReset(BaseModel):
    email: str
    pin: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) != 24:
            raise ValueError('Password must be exactly 24 characters')
        return v

class ThreatLevel(BaseModel):
    level: str  # "bajo", "medio", "alto"
    color: str  # color hex
    priority: int

class Threat(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    threat_type: str  # "leak", "malware", "hack", "vulnerability"
    level: str  # "bajo", "medio", "alto"
    country: str
    country_code: str
    url: Optional[str] = None
    image_url: Optional[str] = None
    social_reference: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    is_active: bool = True

class ThreatCreate(BaseModel):
    title: str
    description: str
    threat_type: str
    level: str
    country: str
    country_code: str
    url: Optional[str] = None
    image_url: Optional[str] = None
    social_reference: Optional[str] = None

class LanguageDetection(BaseModel):
    country_code: str
    language: str
    ip: str

# Language mapping
COUNTRY_LANGUAGE_MAP = {
    "ES": "es", "MX": "es", "AR": "es", "CO": "es", "PE": "es", "CL": "es",
    "VE": "es", "EC": "es", "BO": "es", "PY": "es", "UY": "es", "CR": "es",
    "PA": "es", "NI": "es", "HN": "es", "SV": "es", "GT": "es", "DO": "es", "CU": "es",
    "US": "en", "GB": "en", "CA": "en", "AU": "en", "NZ": "en", "IE": "en",
    "ZA": "en", "SG": "en", "HK": "en", "IN": "en", "PK": "en", "BD": "en",
    "BR": "pt", "PT": "pt", "AO": "pt", "MZ": "pt",
    "FR": "fr", "BE": "fr", "CH": "fr", "LU": "fr", "MC": "fr",
    "DE": "de", "AT": "de", "IT": "it", "RU": "ru", "CN": "zh", "JP": "ja"
}

# Helper functions
def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    # Check proxy headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "127.0.0.1"

async def detect_language_by_ip(ip: str) -> str:
    """Detect language based on IP geolocation"""
    try:
        # Skip private IPs
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '::1':
            return "es"  # Default to Spanish
        
        # Use ipapi.co for free geolocation
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://ipapi.co/{ip}/json/", timeout=3)
            if response.status_code == 200:
                data = response.json()
                country_code = data.get('country_code', '').upper()
                return COUNTRY_LANGUAGE_MAP.get(country_code, "es")
    except Exception as e:
        logging.warning(f"Language detection failed for IP {ip}: {e}")
    
    return "es"  # Default fallback

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def generate_qr_code(url: str) -> str:
    """Generate QR code for URL and return as base64"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="red", back_color="black")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

# Language detection endpoint
@api_router.get("/detect-language")
async def detect_language(request: Request):
    """Detect user language based on IP"""
    client_ip = get_client_ip(request)
    language = await detect_language_by_ip(client_ip)
    
    return {
        "ip": client_ip,
        "language": language,
        "detected_at": datetime.utcnow()
    }

# Authentication endpoints
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    """Register new user"""
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        pin_hash=hash_password(user_data.pin),
        phone=user_data.phone,
        is_admin=False  # First user could be admin
    )
    
    # Make first user admin
    user_count = await db.users.count_documents({})
    if user_count == 0:
        user.is_admin = True
    
    user_dict = user.dict()
    await db.users.insert_one(user_dict)
    
    # Create access token
    access_token = create_access_token(data={"sub": user.email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "is_admin": user.is_admin
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Update last login
    await db.users.update_one(
        {"email": user_data.email},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    access_token = create_access_token(data={"sub": user["email"]})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user["id"],
        "is_admin": user.get("is_admin", False)
    }

@api_router.post("/auth/reset-password")
async def reset_password(reset_data: PasswordReset):
    """Reset password using PIN"""
    user = await db.users.find_one({"email": reset_data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not verify_password(reset_data.pin, user["pin_hash"]):
        raise HTTPException(status_code=401, detail="Invalid PIN")
    
    # Update password
    new_password_hash = hash_password(reset_data.new_password)
    await db.users.update_one(
        {"email": reset_data.email},
        {"$set": {"password_hash": new_password_hash}}
    )
    
    return {"message": "Password reset successfully"}

# Threat management endpoints
@api_router.get("/threats")
async def get_threats(
    country: Optional[str] = None,
    level: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 100
):
    """Get threats with filtering"""
    filter_dict = {"is_active": True}
    
    if country:
        filter_dict["country_code"] = country.upper()
    if level:
        filter_dict["level"] = level
    if threat_type:
        filter_dict["threat_type"] = threat_type
    
    threats = await db.threats.find(filter_dict).sort("created_at", -1).limit(limit).to_list(length=None)
    return [Threat(**threat) for threat in threats]

@api_router.post("/threats")
async def create_threat(threat_data: ThreatCreate, admin: User = Depends(get_admin_user)):
    """Create new threat (admin only)"""
    threat = Threat(**threat_data.dict())
    threat_dict = threat.dict()
    
    await db.threats.insert_one(threat_dict)
    return threat

@api_router.put("/threats/{threat_id}")
async def update_threat(
    threat_id: str, 
    threat_data: ThreatCreate, 
    admin: User = Depends(get_admin_user)
):
    """Update threat (admin only)"""
    update_data = threat_data.dict()
    update_data["updated_at"] = datetime.utcnow()
    
    result = await db.threats.update_one(
        {"id": threat_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {"message": "Threat updated successfully"}

@api_router.delete("/threats/{threat_id}")
async def delete_threat(threat_id: str, admin: User = Depends(get_admin_user)):
    """Delete threat (admin only)"""
    result = await db.threats.update_one(
        {"id": threat_id},
        {"$set": {"is_active": False}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {"message": "Threat deleted successfully"}

@api_router.post("/threats/upload-json")
async def upload_threats_json(
    file: UploadFile = File(...),
    admin: User = Depends(get_admin_user)
):
    """Upload threats from JSON file (admin only)"""
    try:
        content = await file.read()
        threats_data = json.loads(content)
        
        if not isinstance(threats_data, list):
            raise HTTPException(status_code=400, detail="JSON must contain an array of threats")
        
        inserted_count = 0
        for threat_data in threats_data:
            try:
                threat = Threat(**threat_data)
                await db.threats.insert_one(threat.dict())
                inserted_count += 1
            except Exception as e:
                logging.warning(f"Failed to insert threat: {e}")
                continue
        
        return {
            "message": f"Successfully imported {inserted_count} threats",
            "total_processed": len(threats_data)
        }
    
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

# QR Code generation
@api_router.get("/qr-code")
async def generate_app_qr():
    """Generate QR code for app access"""
    app_url = "https://hack-monitor.preview.emergentagent.com"  # Your app URL
    qr_code = generate_qr_code(app_url)
    
    return {
        "qr_code": qr_code,
        "url": app_url,
        "generated_at": datetime.utcnow()
    }

# Statistics endpoint
@api_router.get("/stats")
async def get_stats():
    """Get threat statistics"""
    total_threats = await db.threats.count_documents({"is_active": True})
    
    # Count by level
    level_stats = await db.threats.aggregate([
        {"$match": {"is_active": True}},
        {"$group": {"_id": "$level", "count": {"$sum": 1}}}
    ]).to_list(length=None)
    
    # Count by type
    type_stats = await db.threats.aggregate([
        {"$match": {"is_active": True}},
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
    ]).to_list(length=None)
    
    # Count by country
    country_stats = await db.threats.aggregate([
        {"$match": {"is_active": True}},
        {"$group": {"_id": "$country_code", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]).to_list(length=None)
    
    return {
        "total_threats": total_threats,
        "by_level": {item["_id"]: item["count"] for item in level_stats},
        "by_type": {item["_id"]: item["count"] for item in type_stats},
        "by_country": {item["_id"]: item["count"] for item in country_stats}
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()