"""
Database Schemas for Lineage 2 website

Each Pydantic model represents a collection in MongoDB.
Class name lowercased = collection name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal

class Account(BaseModel):
    """
    Accounts collection schema
    Collection name: "account"
    """
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    role: Literal["user", "admin"] = Field("user")
    avatar_url: Optional[str] = None
    is_active: bool = True

class News(BaseModel):
    """
    News posts for the homepage
    Collection name: "news"
    """
    title: str
    content: str
    author: str
    published: bool = True

# The database helper will use these schemas for validation in the viewer tools.
