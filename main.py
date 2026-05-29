import os
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field, validator
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

JWT_SECRET_KEY = os.getenv("APP_STRONG_JWT_SECRET", "9f8a2c3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

STATIC_FERNET_KEY = os.getenv("APP_FIELD_ENC_KEY", Fernet.generate_key().decode())
cipher_suite = Fernet(STATIC_FERNET_KEY.encode())

app = FastAPI(title="SalamaHealth Secure Backend", version="1.0.0")
password_crypto_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_authorization_mapping = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

class UserAuthenticationSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=64)

class UserRegistrationSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=64)
    role: str = Field(..., description="Must be structurally assigned to 'Doctor' or 'Patient'")

    @validator('role')
    def enforce_strict_roles(cls, value):
        if value not in ['Doctor', 'Patient']:
            raise ValueError("Role parameter out of valid scope bounds.")
        return value

    @validator('password')
    def verify_password_entropy(cls, value):
        if not re.search(r"[A-Z]", value) or not re.search(r"[a-z]", value):
            raise ValueError("Password missing uppercase/lowercase character verification.")
        if not re.search(r"[0-9]", value) or not re.search(r"[!@#$%^&*()]", value):
            raise ValueError("Password missing numerical or special characters.")
        return value

class MedicalRecordSchema(BaseModel):
    patient_id: int = Field(..., gt=0)
    diagnosis_details: str = Field(..., min_length=10, max_length=2000)

PSEUDO_USER_TABLE: Dict[str, Dict[str, Any]] = {}
PSEUDO_MEDICAL_RECORDS_TABLE: Dict[int, Dict[str, Any]] = {}

def compute_secure_hash(password: str) -> str:
    return password_crypto_context.hash(password)

def verify_hash_match(plain_password: str, hashed_password: str) -> bool:
    return password_crypto_context.verify(plain_password, hashed_password)

def generate_session_token(payload_claims: dict) -> str:
    claims_identity = payload_claims.copy()
    expiration_timeline = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    claims_identity.update({"exp": expiration_timeline})
    return jwt.encode(claims_identity, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def extract_authenticated_context(token: str = Depends(oauth2_authorization_mapping)) -> dict:
    auth_failure_exception = HTTPException(status_code=401, detail="Token verification failed.")
    try:
        token_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_email: Optional[str] = token_payload.get("sub")
        assigned_role: Optional[str] = token_payload.get("role")
        if user_email is None or assigned_role is None:
            raise auth_failure_exception
        return {"email": user_email, "role": assigned_role}
    except JWTError:
        raise auth_failure_exception

def restrict_to_role(allowed_role_scope: str):
    def validation_callback(current_identity_context: dict = Depends(extract_authenticated_context)):
        if current_identity_context["role"] != allowed_role_scope:
            raise HTTPException(status_code=403, detail="Access Denied.")
        return current_identity_context
    return validation_callback

@app.post("/api/v1/auth/register", status_code=201)
async def service_register_endpoint(registration_payload: UserRegistrationSchema):
    if registration_payload.email in PSEUDO_USER_TABLE:
        raise HTTPException(status_code=400, detail="Account exists.")
    PSEUDO_USER_TABLE[registration_payload.email] = {
        "email": registration_payload.email,
        "password_hash": compute_secure_hash(registration_payload.password),
        "role": registration_payload.role
    }
    return {"status": "Success"}

@app.post("/api/v1/auth/login")
async def service_login_endpoint(auth_payload: UserAuthenticationSchema):
    user_record = PSEUDO_USER_TABLE.get(auth_payload.email)
    if not user_record or not verify_hash_match(auth_payload.password, user_record["password_hash"]):
        raise HTTPException(status_code=401, detail="Authentication parameters mismatch.")
    session_token = generate_session_token({"sub": user_record["email"], "role": user_record["role"]})
    return {"access_token": session_token, "token_type": "bearer"}

@app.post("/api/v1/records/upload", status_code=201)
async def service_upload_record(record_payload: MedicalRecordSchema, active_operator: dict = Depends(restrict_to_role("Doctor"))):
    opaque_ciphertext_blob = cipher_suite.encrypt(record_payload.diagnosis_details.encode())
    PSEUDO_MEDICAL_RECORDS_TABLE[record_payload.patient_id] = {
        "signing_doctor": active_operator["email"],
        "encrypted_payload": opaque_ciphertext_blob,
        "record_timestamp": datetime.utcnow()
    }
    return {"status": "Securely Transmitted"}

@app.get("/api/v1/records/view/{patient_id}")
async def service_view_record(patient_id: int, active_operator: dict = Depends(extract_authenticated_context)):
    target_record = PSEUDO_MEDICAL_RECORDS_TABLE.get(patient_id)
    if not target_record:
        raise HTTPException(status_code=404, detail="Not found.")
    cleartext_diagnosis_string = cipher_suite.decrypt(target_record["encrypted_payload"]).decode()
    return {
        "patient_index_id": patient_id,
        "attending_practitioner": target_record["signing_doctor"],
        "decrypted_clinical_metrics": cleartext_diagnosis_string
    }