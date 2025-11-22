import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

app = FastAPI(title="Lineage 2 Site API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------
# Security Utilities
# -----------------
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
except Exception as e:
    pwd_context = None

TOKEN_TTL_HOURS = 24


def hash_password(password: str) -> str:
    if not pwd_context:
        raise HTTPException(status_code=500, detail="Password hashing not available")
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    if not pwd_context:
        return False
    return pwd_context.verify(password, hashed)


# -----------------
# Models
# -----------------
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class NewsCreate(BaseModel):
    title: str
    content: str

class UserPublic(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str
    avatar_url: Optional[str] = None
    is_active: bool = True

# -----------------
# Helpers
# -----------------

def to_public_user(doc: dict) -> UserPublic:
    return UserPublic(
        id=str(doc.get("_id")),
        username=doc.get("username"),
        email=doc.get("email"),
        role=doc.get("role", "user"),
        avatar_url=doc.get("avatar_url"),
        is_active=doc.get("is_active", True)
    )


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    token = authorization.split(" ", 1)[1]

    session = db["session"].find_one({"token": token}) if db else None
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Expiry check
    exp = session.get("expires_at")
    if exp and datetime.now(timezone.utc) > exp:
        db["session"].delete_one({"_id": session["_id"]})
        raise HTTPException(status_code=401, detail="Session expired")

    user = db["account"].find_one({"_id": session.get("account_id")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User disabled")
    return user


def require_admin(user: dict):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

# -----------------
# Basic routes
# -----------------
@app.get("/")
def read_root():
    return {"message": "Lineage 2 Backend Running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:80]}"
    return response

# -----------------
# Auth routes
# -----------------
@app.post("/api/auth/register")
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    # Uniqueness check
    exists = db["account"].find_one({"$or": [{"username": payload.username}, {"email": payload.email}]})
    if exists:
        raise HTTPException(status_code=400, detail="Username or email already in use")

    account_doc = {
        "username": payload.username,
        "email": str(payload.email),
        "password_hash": hash_password(payload.password),
        "role": "user",
        "avatar_url": None,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result_id = db["account"].insert_one(account_doc).inserted_id

    # Auto login after register
    token = str(uuid4())
    session_doc = {
        "token": token,
        "account_id": result_id,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)
    }
    db["session"].insert_one(session_doc)

    return {"token": token, "user": to_public_user(account_doc).model_dump()}


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    user = db["account"].find_one({
        "$or": [
            {"username": payload.username_or_email},
            {"email": payload.username_or_email}
        ]
    })
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = str(uuid4())
    session_doc = {
        "token": token,
        "account_id": user["_id"],
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)
    }
    db["session"].insert_one(session_doc)

    return {"token": token, "user": to_public_user(user).model_dump()}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return {"user": to_public_user(user).model_dump()}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization:
        return {"ok": True}
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        if db:
            db["session"].delete_many({"token": token})
    return {"ok": True}

# -----------------
# News
# -----------------
@app.get("/api/news")
def list_news() -> List[dict]:
    items = db["news"].find({"published": True}).sort("created_at", -1) if db else []
    return [
        {
            "id": str(i.get("_id")),
            "title": i.get("title"),
            "content": i.get("content"),
            "author": i.get("author"),
            "created_at": i.get("created_at")
        }
        for i in items
    ]

@app.post("/api/news")
def create_news(payload: NewsCreate, user: dict = Depends(get_current_user)):
    require_admin(user)
    doc = {
        "title": payload.title,
        "content": payload.content,
        "author": user.get("username"),
        "published": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    _id = db["news"].insert_one(doc).inserted_id
    return {"id": str(_id)}

# -----------------
# Admin: users management
# -----------------
@app.get("/api/admin/users")
def admin_users(user: dict = Depends(get_current_user)):
    require_admin(user)
    users = db["account"].find().sort("created_at", -1)
    return [to_public_user(u).model_dump() for u in users]

@app.patch("/api/admin/users/{user_id}/role")
def set_role(user_id: str, role: str, user: dict = Depends(get_current_user)):
    require_admin(user)
    if role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")
    from bson import ObjectId
    try:
        oid = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user id")
    db["account"].update_one({"_id": oid}, {"$set": {"role": role, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


# Legacy hello
@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
