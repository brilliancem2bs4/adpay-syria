from fastapi import FastAPI, APIRouter, HTTPException, Depends, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Literal
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import base64
import uuid

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

# Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    phone: str
    role: str = "client"
    created_at: str

class AdRequestCreate(BaseModel):
    location: str
    product_names: str
    other_info: Optional[str] = ""
    payment_type: Literal["per-ad", "subscription"]

class AdRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    client_id: str
    client_name: str
    client_email: str
    location: str
    product_names: str
    other_info: str
    photos: List[str] = []
    payment_type: str
    status: str = "pending"
    created_at: str

class PaymentCreate(BaseModel):
    ad_request_id: str
    payment_method: Literal["sham_cash", "syriatel"]

class Payment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    ad_request_id: str
    payment_method: str
    screenshot_url: str
    status: str = "pending"
    created_at: str
    verified_at: Optional[str] = None

class SubscriptionCreate(BaseModel):
    payment_method: Literal["sham_cash", "syriatel"]

class Subscription(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    client_id: str
    client_name: str
    client_email: str
    start_date: str
    end_date: str
    status: str = "active"
    payment_screenshot: str
    payment_method: str
    created_at: str

class AdminSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sham_cash_qr: str = ""
    syriatel_qr: str = ""

class AdminSettingsUpdate(BaseModel):
    sham_cash_qr: Optional[str] = None
    syriatel_qr: Optional[str] = None

# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Invalid authentication")

async def get_admin_user(current_user = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# Auth routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = {
        "id": str(uuid.uuid4()),
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "phone": user_data.phone,
        "role": "client",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_dict)
    token = create_token(user_dict['id'], user_dict['email'], user_dict['role'])
    
    return {"token": token, "user": User(**{k: v for k, v in user_dict.items() if k != 'password'})}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user['id'], user['email'], user['role'])
    return {"token": token, "user": User(**{k: v for k, v in user.items() if k != 'password'})}

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user['user_id']}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**user)

# File upload
@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user = Depends(get_current_user)):
    contents = await file.read()
    file_id = str(uuid.uuid4())
    base64_data = base64.b64encode(contents).decode('utf-8')
    
    file_doc = {
        "id": file_id,
        "filename": file.filename,
        "data": base64_data,
        "content_type": file.content_type,
        "uploaded_by": current_user['user_id'],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.files.insert_one(file_doc)
    return {"file_id": file_id, "url": f"/api/files/{file_id}"}

@api_router.get("/files/{file_id}")
async def get_file(file_id: str):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    from fastapi.responses import Response
    file_data = base64.b64decode(file_doc['data'])
    return Response(content=file_data, media_type=file_doc.get('content_type', 'application/octet-stream'))

# Ad Requests
@api_router.post("/ad-requests", response_model=AdRequest)
async def create_ad_request(ad_data: AdRequestCreate, current_user = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user['user_id']}, {"_id": 0})
    
    ad_dict = {
        "id": str(uuid.uuid4()),
        "client_id": current_user['user_id'],
        "client_name": user['name'],
        "client_email": user['email'],
        "location": ad_data.location,
        "product_names": ad_data.product_names,
        "other_info": ad_data.other_info,
        "photos": [],
        "payment_type": ad_data.payment_type,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.ad_requests.insert_one(ad_dict)
    return AdRequest(**ad_dict)

@api_router.post("/ad-requests/{ad_id}/photos")
async def add_photos(ad_id: str, file_ids: List[str], current_user = Depends(get_current_user)):
    ad = await db.ad_requests.find_one({"id": ad_id, "client_id": current_user['user_id']}, {"_id": 0})
    if not ad:
        raise HTTPException(status_code=404, detail="Ad request not found")
    
    photo_urls = [f"/api/files/{fid}" for fid in file_ids]
    await db.ad_requests.update_one(
        {"id": ad_id},
        {"$set": {"photos": photo_urls}}
    )
    
    return {"success": True, "photos": photo_urls}

@api_router.get("/ad-requests", response_model=List[AdRequest])
async def get_ad_requests(current_user = Depends(get_current_user)):
    if current_user['role'] == 'admin':
        ads = await db.ad_requests.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        ads = await db.ad_requests.find({"client_id": current_user['user_id']}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    return [AdRequest(**ad) for ad in ads]

@api_router.get("/ad-requests/{ad_id}", response_model=AdRequest)
async def get_ad_request(ad_id: str, current_user = Depends(get_current_user)):
    query = {"id": ad_id}
    if current_user['role'] != 'admin':
        query["client_id"] = current_user['user_id']
    
    ad = await db.ad_requests.find_one(query, {"_id": 0})
    if not ad:
        raise HTTPException(status_code=404, detail="Ad request not found")
    
    return AdRequest(**ad)

@api_router.patch("/ad-requests/{ad_id}/status")
async def update_ad_status(ad_id: str, status: str, current_user = Depends(get_admin_user)):
    result = await db.ad_requests.update_one(
        {"id": ad_id},
        {"$set": {"status": status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Ad request not found")
    
    return {"success": True}

# Payments
@api_router.post("/payments", response_model=Payment)
async def create_payment(payment_data: PaymentCreate, current_user = Depends(get_current_user)):
    ad = await db.ad_requests.find_one({"id": payment_data.ad_request_id, "client_id": current_user['user_id']}, {"_id": 0})
    if not ad:
        raise HTTPException(status_code=404, detail="Ad request not found")
    
    payment_dict = {
        "id": str(uuid.uuid4()),
        "ad_request_id": payment_data.ad_request_id,
        "payment_method": payment_data.payment_method,
        "screenshot_url": "",
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verified_at": None
    }
    
    await db.payments.insert_one(payment_dict)
    return Payment(**payment_dict)

@api_router.post("/payments/{payment_id}/screenshot")
async def upload_payment_screenshot(payment_id: str, file_id: str, current_user = Depends(get_current_user)):
    screenshot_url = f"/api/files/{file_id}"
    result = await db.payments.update_one(
        {"id": payment_id},
        {"$set": {"screenshot_url": screenshot_url}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    return {"success": True, "screenshot_url": screenshot_url}

@api_router.get("/payments", response_model=List[Payment])
async def get_payments(current_user = Depends(get_current_user)):
    if current_user['role'] == 'admin':
        payments = await db.payments.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        ad_ids = [ad['id'] for ad in await db.ad_requests.find({"client_id": current_user['user_id']}, {"_id": 0, "id": 1}).to_list(1000)]
        payments = await db.payments.find({"ad_request_id": {"$in": ad_ids}}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    return [Payment(**p) for p in payments]

@api_router.patch("/payments/{payment_id}/verify")
async def verify_payment(payment_id: str, current_user = Depends(get_admin_user)):
    payment = await db.payments.find_one({"id": payment_id}, {"_id": 0})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")
    
    await db.payments.update_one(
        {"id": payment_id},
        {"$set": {"status": "verified", "verified_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    await db.ad_requests.update_one(
        {"id": payment['ad_request_id']},
        {"$set": {"status": "paid"}}
    )
    
    return {"success": True}

# Subscriptions
@api_router.post("/subscriptions", response_model=Subscription)
async def create_subscription(sub_data: SubscriptionCreate, current_user = Depends(get_current_user)):
    user = await db.users.find_one({"id": current_user['user_id']}, {"_id": 0})
    
    start_date = datetime.now(timezone.utc)
    end_date = start_date + timedelta(days=30)
    
    sub_dict = {
        "id": str(uuid.uuid4()),
        "client_id": current_user['user_id'],
        "client_name": user['name'],
        "client_email": user['email'],
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "status": "pending",
        "payment_screenshot": "",
        "payment_method": sub_data.payment_method,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.subscriptions.insert_one(sub_dict)
    return Subscription(**sub_dict)

@api_router.post("/subscriptions/{sub_id}/screenshot")
async def upload_subscription_screenshot(sub_id: str, file_id: str, current_user = Depends(get_current_user)):
    screenshot_url = f"/api/files/{file_id}"
    result = await db.subscriptions.update_one(
        {"id": sub_id, "client_id": current_user['user_id']},
        {"$set": {"payment_screenshot": screenshot_url}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    return {"success": True, "screenshot_url": screenshot_url}

@api_router.get("/subscriptions/my", response_model=List[Subscription])
async def get_my_subscriptions(current_user = Depends(get_current_user)):
    subs = await db.subscriptions.find({"client_id": current_user['user_id']}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return [Subscription(**s) for s in subs]

@api_router.get("/subscriptions", response_model=List[Subscription])
async def get_all_subscriptions(current_user = Depends(get_admin_user)):
    subs = await db.subscriptions.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return [Subscription(**s) for s in subs]

@api_router.patch("/subscriptions/{sub_id}/verify")
async def verify_subscription(sub_id: str, current_user = Depends(get_admin_user)):
    result = await db.subscriptions.update_one(
        {"id": sub_id},
        {"$set": {"status": "active"}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    return {"success": True}

# Admin Settings
@api_router.get("/admin/settings", response_model=AdminSettings)
async def get_admin_settings():
    settings = await db.admin_settings.find_one({}, {"_id": 0})
    if not settings:
        default_settings = {"sham_cash_qr": "", "syriatel_qr": ""}
        await db.admin_settings.insert_one(default_settings)
        return AdminSettings(**default_settings)
    return AdminSettings(**settings)

@api_router.patch("/admin/settings")
async def update_admin_settings(settings: AdminSettingsUpdate, current_user = Depends(get_admin_user)):
    update_data = {k: v for k, v in settings.model_dump().items() if v is not None}
    
    if update_data:
        await db.admin_settings.update_one(
            {},
            {"$set": update_data},
            upsert=True
        )
    
    return {"success": True}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
