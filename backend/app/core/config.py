from pydantic_settings import BaseSettings
from typing import List, Optional, Dict, Any
import os
from pathlib import Path


class Settings(BaseSettings):
    # Base settings
    PROJECT_NAME: str = "Static Malware Analyzer"
    API_V1_STR: str = "/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "highly-secure-secret-key-replace-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 10
    
    # CORS settings
    CORS_ORIGINS: List[str] = [
        "*",  # Frontend in development
         # Production domain
    ]
    
    # File upload settings
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "/tmp/malware_analyzer/uploads")
    MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024  # 50 MB limit
    ALLOWED_EXTENSIONS: List[str] = ["exe", "pdf"]
    
    # Analysis settings
    ANALYSIS_TIMEOUT: int = 300  # 5 minutes timeout for analysis
    
    # ML Model settings
    MODEL_PATH: str = os.getenv("MODEL_PATH", "trained_models/trained.pkl")
    CONFIDENCE_THRESHOLD: float = 0.7  # Threshold for malware detection
    
    # Reports
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "/tmp/malware_analyzer/reports")
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./malware_analyzer.db")
    
    # Sandbox execution (disabled by default for security reasons)
    ENABLE_DYNAMIC_ANALYSIS: bool = False
    SANDBOX_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

    def __init__(self, **data: Any):
        super().__init__(**data)
        
        # Create upload and reports directories if they don't exist
        Path(self.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.REPORTS_DIR).mkdir(parents=True, exist_ok=True)


settings = Settings()