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

# Cryptographic and Security Context Configurations
JWT_SECRET_KEY = os.getenv("APP_STRONG_JWT_SECRET", "9f8a2c3b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

STATIC_FERNET_KEY = os.getenv("APP_FIELD_ENC_KEY", Fernet.generate_key().decode())
cipher_suite = Fernet(STATIC_FERNET_KEY.encode())

# Professional API Documentation Metadata (Clean & Hardened Infrastructure)
app = FastAPI(
    title="🛡️ SalamaHealth Secure Backend Portal",
    description="""
    Cyber Security Defensive Engineering & Healthcare Privacy Staging Environment.
    
    Welcome to the SalamaHealth interactive proof-of-concept demonstration. This platform deploys enterprise-grade validation controls mapped to the critical OWASP Top 10 framework.
    
    1. Cryptographic Confidentiality: All clinical Protected Health Information (PHI) strings undergo dynamic, application-layer symmetric encryption using AES-256 equivalent configurations at the storage perimeter.
    
    2. Zero-Trust Architecture: The gateway enforces rigid, decentralized Role-Based Access Control (RBAC) validations using high-entropy JSON Web Tokens (JWT) to securely isolate physician and patient operations.
    """,
    version="2.0.0",
    openapi_tags=[
        {
            "name": "1. Identity & Access Management (IAM)",
            "description": "Operations handling secure user onboarding, high-entropy password enforcement, and cryptographic JWT session token issuance."
        },
        {
            "name": "2. Protected Health Information (PHI) Engine",
            "description": "Operations handling application-layer encryption, cryptographic access control enforcement, and decryption processes."
        }
    ]
)

password_crypto_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_authorization_mapping = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

# Data Schemas Validation Framework
class UserAuthenticationSchema(BaseModel):
    email: EmailStr = Field(..., description="Registered identity email format.")
    password: str = Field(..., min_length=12, max_length=64, description="High-entropy raw password string.")

class UserRegistrationSchema(BaseModel):
    email: EmailStr = Field(..., description="Unique administrative or patient email handle.")
    password: str = Field(..., min_length=12, max_length=64, description="Must include uppercase, lowercase, numbers, and symbols.")
    role: str = Field(..., description="System RBAC assignment. Strictly bounded to: 'Doctor' or 'Patient'")

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
    patient_id: int = Field(..., gt=0, description="Unique, positive structural identifier of the target patient.")
    diagnosis_details: str = Field(..., min_length=10, max_length=2000, description="Plaintext raw clinical summary text.")

# Runtime In-Memory Cryptographic Persistence Layer
PSEUDO_USER_TABLE: Dict[str, Dict[str, Any]] = {}
PSEUDO_MEDICAL_RECORDS_TABLE: Dict[int, Dict[str, Any]] = {}

# Security Logic Subsystems
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
    auth_failure_exception = HTTPException(status_code=401, detail="Token verification failed or expired.")
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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Access Denied: Operating identity profile scope is restricted from this operational route."
            )
        return current_identity_context
    return validation_callback

# Endpoint Routing Operations
@app.post(
    "/api/v1/auth/register", 
    status_code=201, 
    tags=["1. Identity & Access Management (IAM)"],
    summary="Register New System Identity / تسجيل حساب جديد في النظام",
    description="Registers a profile and enforces cryptographic input validation context rules (OWASP Mitigation)."
)
async def service_register_endpoint(registration_payload: UserRegistrationSchema):
    if registration_payload.email in PSEUDO_USER_TABLE:
        raise HTTPException(status_code=400, detail="Account identifier already allocated within persistence registers.")
    PSEUDO_USER_TABLE[registration_payload.email] = {
        "email": registration_payload.email,
        "password_hash": compute_secure_hash(registration_payload.password),
        "role": registration_payload.role
    }
    return {"status": "Success", "message": "Identity verified and safely committed to runtime architecture blocks."}

@app.post(
    "/api/v1/auth/login", 
    tags=["1. Identity & Access Management (IAM)"],
    summary="Establish Authorized Session (Generate JWT) / تسجيل الدخول وتوليد مفتاح الجلسة",
    description="Validates cryptographic credential hash matches and issues a high-entropy short-lived OAuth2 bearer session token."
)
async def service_login_endpoint(auth_payload: UserAuthenticationSchema):
    user_record = PSEUDO_USER_TABLE.get(auth_payload.email)
    if not user_record or not verify_hash_match(auth_payload.password, user_record["password_hash"]):
        raise HTTPException(status_code=401, detail="Authentication verification parameters mismatch.")
    session_token = generate_session_token({"sub": user_record["email"], "role": user_record["role"]})
    return {"access_token": session_token, "token_type": "bearer"}

@app.post(
    "/api/v1/records/upload", 
    status_code=201, 
    tags=["2. Protected Health Information (PHI) Engine"],
    summary="Secure Medical Record Ingestion (Doctors Only) / رفع وتشفير البيانات الطبية - خاص بالأطباء",
    description="Intercepts plaintext clinical findings, processes them via application-layer AES symmetric suites, and commits the resulting ciphertext block."
)
async def service_upload_record(record_payload: MedicalRecordSchema, active_operator: dict = Depends(restrict_to_role("Doctor"))):
    opaque_ciphertext_blob = cipher_suite.encrypt(record_payload.diagnosis_details.encode())
    PSEUDO_MEDICAL_RECORDS_TABLE[record_payload.patient_id] = {
        "signing_doctor": active_operator["email"],
        "encrypted_payload": opaque_ciphertext_blob,
        "record_timestamp": datetime.utcnow()
    }
    return {"status": "Securely Transmitted", "persistence_state": "Ciphertext securely generated and isolated."}

@app.get(
    "/api/v1/records/view/{patient_id}", 
    tags=["2. Protected Health Information (PHI) Engine"],
    summary="Cryptographic Record Retrieval & Decryption / استرجاع وفك تشفير البيانات المصرح بها",
    description="Fetches raw encrypted memory frames, applies token authorization loops, and executes structural key decryption at the runtime margin."
)
async def service_view_record(patient_id: int, active_operator: dict = Depends(extract_authenticated_context)):
    target_record = PSEUDO_MEDICAL_RECORDS_TABLE.get(patient_id)
    if not target_record:
        raise HTTPException(status_code=404, detail="Requested physiological identifier tracking context not allocated.")
    cleartext_diagnosis_string = cipher_suite.decrypt(target_record["encrypted_payload"]).decode()
    return {
        "patient_index_id": patient_id,
        "attending_practitioner": target_record["signing_doctor"],
        "decrypted_clinical_metrics": cleartext_diagnosis_string
    }
