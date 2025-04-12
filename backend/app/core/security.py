from datetime import datetime, timedelta
from typing import Optional, Union
import hashlib
import os
import magic
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, UploadFile
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Setup password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token with expiration time
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    """
    Verify JWT token and return payload
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError as e:
        logger.error(f"JWT verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash
    """
    return pwd_context.verify(plain_password, hashed_password)

# File security functions
def validate_file_type(file: UploadFile) -> str:
    """
    Validate file type and extension
    Returns the detected file type or raises an exception
    """
    # First check the extension
    extension = file.filename.split(".")[-1].lower()
    if extension not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type not allowed. Allowed types: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    # Reset file position to start
    file.file.seek(0)
    
    # Read a chunk of the file to detect its MIME type
    chunk = file.file.read(8192)  # Read first 8KB
    mime = magic.Magic(mime=True)
    detected_type = mime.from_buffer(chunk)
    
    # Reset file position again
    file.file.seek(0)
    
    # Validate detected type
    if extension == "exe" and not detected_type.startswith(("application/x-msdownload", "application/x-dosexec")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File does not match its extension. Detected: {detected_type}"
        )
    elif extension == "pdf" and detected_type != "application/pdf":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File does not match its extension. Detected: {detected_type}"
        )
    
    return detected_type

def save_upload_file(file: UploadFile, file_type: str) -> str:
    """
    Save uploaded file with a secure random name
    Returns the path to the saved file
    """
    # Create secure random filename
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    random_suffix = os.urandom(8).hex()
    extension = file.filename.split(".")[-1].lower()
    secure_filename = f"{timestamp}_{random_suffix}.{extension}"
    
    # Create the full file path
    file_path = os.path.join(settings.UPLOAD_DIR, secure_filename)
    
    # Save the file
    try:
        with open(file_path, "wb") as buffer:
            # Reset file position to start
            file.file.seek(0)
            buffer.write(file.file.read())
    except Exception as e:
        logger.error(f"File save error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error saving file"
        )
    
    logger.info(f"File saved: {file_path}")
    return file_path

def compute_file_hash(file_path: str) -> dict:
    """
    Compute various hashes for a file
    """
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read and update hash in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_md5.update(byte_block)
            hash_sha1.update(byte_block)
            hash_sha256.update(byte_block)
    
    return {
        "md5": hash_md5.hexdigest(),
        "sha1": hash_sha1.hexdigest(),
        "sha256": hash_sha256.hexdigest()
    }

def rate_limit_check(client_ip: str) -> bool:
    """
    Simple in-memory rate limiting (should be replaced with Redis in production)
    """
    # This is a simplified implementation
    # In production, use Redis or similar for distributed rate limiting
    return True  # Placeholder, always allow in this example