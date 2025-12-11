import os
import re
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, status, Depends, Body
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from bson import ObjectId
from fastapi.responses import RedirectResponse
from pymongo.errors import DuplicateKeyError

# ---------- config ----------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MASTER_DB = os.getenv("MASTER_DB", "master_db")
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_to_a_strong_secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

# bcrypt has a 72 byte limit — we enforce this to avoid ValueError from passlib
BCRYPT_MAX_BYTES = 72

# ---------- logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("org_service")

# ---------- password context ----------
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

auth_scheme = HTTPBearer()

app = FastAPI(title="Organization Management Service")

# ---------- Mongo client ----------
client = AsyncIOMotorClient(MONGO_URI)
master_db = client[MASTER_DB]
org_meta_col = master_db["organizations"]

# ---------- helpers ----------
def sanitize_org_name(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]", "_", name)
    s = re.sub(r"_+", "_", s).strip("_")
    return f"org_{s.lower()}" if s else f"org_{int(datetime.utcnow().timestamp())}"

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise HTTPException(status_code=400, detail="Invalid password")
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > BCRYPT_MAX_BYTES:
        # reject long passwords for bcrypt; advise client to use shorter password or contact admin
        raise HTTPException(status_code=400, detail=f"Password too long. Max {BCRYPT_MAX_BYTES} bytes allowed for the current hashing scheme.")
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    # defensive: if plain too long, treat as invalid credential (do not attempt hashing)
    if not isinstance(plain, str):
        return False
    pw_bytes = plain.encode("utf-8")
    if len(pw_bytes) > BCRYPT_MAX_BYTES:
        return False
    try:
        return pwd_context.verify(plain, hashed)
    except Exception as e:
        logger.warning("Password verification error: %s", e)
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def _serialize_org_doc(org_doc: dict) -> dict:
    if not org_doc:
        return org_doc
    out = {}
    # top-level fields we expect
    out["organization_name"] = org_doc.get("organization_name")
    out["collection_name"] = org_doc.get("collection_name")
    # admin: convert id to string and remove password_hash
    admin = org_doc.get("admin")
    if isinstance(admin, dict):
        admin_safe = {k: v for k, v in admin.items() if k != "password_hash"}
        # stringify _id if present
        if admin_safe.get("_id") is not None:
            try:
                admin_safe["_id"] = str(admin_safe["_id"])
            except Exception:
                admin_safe["_id"] = admin_safe.get("_id")
        out["admin"] = admin_safe
    else:
        out["admin"] = None
    # created/updated times
    for ts_field in ("created_at", "updated_at"):
        val = org_doc.get(ts_field)
        if val is None:
            out[ts_field] = None
        else:
            try:
                out[ts_field] = val.isoformat()
            except Exception:
                out[ts_field] = str(val)
    # include the master DB id as string (optional)
    if org_doc.get("_id") is not None:
        try:
            out["_id"] = str(org_doc["_id"])
        except Exception:
            out["_id"] = org_doc["_id"]
    return out

async def get_org_by_name_from_master(org_name: str):
    return await org_meta_col.find_one({"organization_name": org_name})

# ---------- pydantic models ----------
class CreateOrgRequest(BaseModel):
    organization_name: str = Field(..., min_length=1)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UpdateOrgRequest(BaseModel):
    organization_name: str = Field(..., min_length=1)
    new_organization_name: Optional[str] = Field(None, min_length=1)
    email: Optional[EmailStr] = None
    password: Optional[str] = None

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ---------- auth dependency ----------
async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        admin_id = payload.get("admin_id")
        organization_name = payload.get("organization_name")
        if admin_id is None or organization_name is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    org_doc = await get_org_by_name_from_master(organization_name)
    if not org_doc:
        raise credentials_exception
    admin = org_doc.get("admin")
    if not admin or str(admin.get("_id")) != admin_id:
        raise credentials_exception

    return {"admin": admin, "organization": org_doc}

# ---------- endpoints ----------
@app.post("/org/create", status_code=201)
async def create_organization(payload: CreateOrgRequest):
    # check duplicates at app level
    existing = await get_org_by_name_from_master(payload.organization_name)
    if existing:
        raise HTTPException(status_code=400, detail="Organization name already exists")

    coll_name = sanitize_org_name(payload.organization_name)

    # validate password length and hash (hash_password raises HTTPException if too long)
    try:
        password_hash = hash_password(payload.password)
    except HTTPException:
        # bubble up the validation error with 400
        raise

    admin_doc = {
        "_id": ObjectId(),
        "email": payload.email,
        "password_hash": password_hash,
        "created_at": datetime.utcnow()
    }

    org_db = client[MASTER_DB]
    try:
        if coll_name not in await org_db.list_collection_names():
            await org_db.create_collection(coll_name)

        org_metadata = {
            "organization_name": payload.organization_name,
            "collection_name": coll_name,
            "connection": {"db": MASTER_DB},
            "admin": admin_doc,
            "created_at": datetime.utcnow()
        }

        res = await org_meta_col.insert_one(org_metadata)
        org_metadata["_id"] = res.inserted_id

    except DuplicateKeyError as dk:
        logger.warning("DuplicateKeyError when creating org: %s", dk)
        raise HTTPException(status_code=400, detail="Organization or admin email already exists")
    except Exception as e:
        logger.exception("Unhandled error in create_organization: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")

    return {
        "message": "Organization created",
        "organization": {
            "organization_name": org_metadata["organization_name"],
            "collection_name": coll_name,
            "created_at": org_metadata["created_at"]
        }
    }

@app.get("/org/get")
async def get_organization(organization_name: str):
    try:
        # try exact match on organization_name first (preferred)
        org_doc = await org_meta_col.find_one({"organization_name": organization_name})
        if not org_doc:
            # fallback: maybe caller sent the collection name (sanitized) instead
            org_doc = await org_meta_col.find_one({"collection_name": organization_name})
        if not org_doc:
            raise HTTPException(status_code=404, detail="Organization not found")

        return _serialize_org_doc(org_doc)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unhandled error in GET /org/get: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.put("/org/update")
async def update_organization(payload: UpdateOrgRequest, current=Depends(get_current_admin)):
    token_org = current["organization"]["organization_name"]
    if token_org != payload.organization_name:
        raise HTTPException(status_code=403, detail="Forbidden: can only update your own organization")

    try:
        org_doc = await get_org_by_name_from_master(payload.organization_name)
        if not org_doc:
            raise HTTPException(status_code=404, detail="Organization not found")

        updates = {}
        # admin update
        if payload.email or payload.password:
            admin = org_doc.get("admin", {})
            if payload.email:
                admin["email"] = payload.email
            if payload.password:
                admin["password_hash"] = hash_password(payload.password)
            admin["updated_at"] = datetime.utcnow()
            updates["admin"] = admin

        # rename organization (and migrate collection)
        if payload.new_organization_name:
            # if new name same as old, ignore
            if payload.new_organization_name == org_doc["organization_name"]:
                pass
            else:
                # ensure uniqueness
                existing = await get_org_by_name_from_master(payload.new_organization_name)
                if existing:
                    raise HTTPException(status_code=400, detail="New organization name already exists")

                old_coll = org_doc["collection_name"]
                new_coll = sanitize_org_name(payload.new_organization_name)

                org_db = client[MASTER_DB]
                # create new collection if not exists
                if new_coll not in await org_db.list_collection_names():
                    await org_db.create_collection(new_coll)

                old_c = org_db[old_coll]
                new_c = org_db[new_coll]

                # stream documents in batches to avoid memory spikes
                async for doc in old_c.find({}):
                    try:
                        await new_c.insert_one(doc)
                    except Exception:
                        _doc = doc.copy()
                        _doc.pop("_id", None)
                        await new_c.insert_one(_doc)

                # drop old collection after copy
                await old_c.drop()

                updates["organization_name"] = payload.new_organization_name
                updates["collection_name"] = new_coll

        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        updates["updated_at"] = datetime.utcnow()
        try:
            await org_meta_col.update_one({"_id": org_doc["_id"]}, {"$set": updates})
        except DuplicateKeyError:
            raise HTTPException(status_code=400, detail="Update would violate unique constraints")

        return {"message": "Organization updated", "updates": updates}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unhandled error in PUT /org/update: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.delete("/org/delete")
async def delete_organization(organization_name: str = Body(...), current=Depends(get_current_admin)):
    token_org = current["organization"]["organization_name"]
    if token_org != organization_name:
        raise HTTPException(status_code=403, detail="Forbidden: can only delete your own organization")

    try:
        org_doc = await get_org_by_name_from_master(organization_name)
        if not org_doc:
            raise HTTPException(status_code=404, detail="Organization not found")

        coll_name = org_doc["collection_name"]
        org_db = client[MASTER_DB]
        if coll_name in await org_db.list_collection_names():
            await org_db[coll_name].drop()
        await org_meta_col.delete_one({"_id": org_doc["_id"]})
        return {"message": f"Organization '{organization_name}' and collection '{coll_name}' deleted"}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unhandled error in DELETE /org/delete: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/admin/login", response_model=TokenResponse)
async def admin_login(payload: AdminLoginRequest):
    org_doc = await org_meta_col.find_one({"admin.email": payload.email})
    if not org_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    admin = org_doc["admin"]
    if not verify_password(payload.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"admin_id": str(admin["_id"]), "organization_name": org_doc["organization_name"]}
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/_health")
async def health():
    return {"status": "ok", "master_db": MASTER_DB}

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")
