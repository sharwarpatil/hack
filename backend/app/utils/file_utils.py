import logging
import os
import shutil
import hashlib
import tempfile
import magic
import time
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_file_mime_type(file_path: str) -> str:
    """
    Get the MIME type of a file
    """
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except Exception as e:
        logger.error(f"Error getting MIME type: {str(e)}")
        return "application/octet-stream"


def get_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Compute multiple hash types for a file
    """
    try:
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
    except Exception as e:
        logger.error(f"Error computing file hashes: {str(e)}")
        return {
            "md5": "",
            "sha1": "",
            "sha256": ""
        }


def is_valid_file_type(file_path: str, allowed_types: List[str]) -> bool:
    """
    Check if a file has an allowed type
    """
    try:
        # Get the file extension
        file_extension = os.path.splitext(file_path)[1].lower().lstrip('.')
        
        # Check if the extension is in the allowed list
        if file_extension not in allowed_types:
            return False
        
        # Get the MIME type and verify it matches expected type
        mime_type = get_file_mime_type(file_path)
        
        if file_extension == "exe" and not mime_type.startswith(("application/x-msdownload", "application/x-dosexec")):
            return False
        
        if file_extension == "pdf" and mime_type != "application/pdf":
            return False
        
        return True
    
    except Exception as e:
        logger.error(f"Error validating file type: {str(e)}")
        return False


def create_temp_copy(file_path: str) -> str:
    """
    Create a temporary copy of a file for analysis
    """
    try:
        # Create a temporary file with the same extension
        file_extension = os.path.splitext(file_path)[1]
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=file_extension)
        temp_file.close()
        
        # Copy the content
        shutil.copy2(file_path, temp_file.name)
        
        return temp_file.name
    
    except Exception as e:
        logger.error(f"Error creating temporary file copy: {str(e)}")
        return file_path  # Return the original path if copying fails


def safely_remove_file(file_path: str) -> bool:
    """
    Safely remove a file, with error handling
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        logger.error(f"Error removing file {file_path}: {str(e)}")
        return False


def clean_old_files(directory: str, max_age_hours: int = 24) -> int:
    """
    Clean up old files from a directory
    Returns the number of files removed
    """
    try:
        if not os.path.exists(directory):
            return 0
        
        files_removed = 0
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            
            # Skip directories
            if os.path.isdir(file_path):
                continue
            
            # Check file modification time
            file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            
            if file_mod_time < cutoff_time:
                if safely_remove_file(file_path):
                    files_removed += 1
        
        return files_removed
    
    except Exception as e:
        logger.error(f"Error cleaning old files from {directory}: {str(e)}")
        return 0


def ensure_directory_exists(directory_path: str) -> bool:
    """
    Ensure a directory exists, create it if it doesn't
    """
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {directory_path}: {str(e)}")
        return False


def get_file_size(file_path: str) -> int:
    """
    Get the size of a file in bytes
    """
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        logger.error(f"Error getting file size: {str(e)}")
        return 0


def get_directory_size(directory_path: str) -> int:
    """
    Get the total size of all files in a directory
    """
    try:
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                total_size += os.path.getsize(file_path)
        
        return total_size
    except Exception as e:
        logger.error(f"Error calculating directory size: {str(e)}")
        return 0


def list_files_by_extension(directory_path: str, extensions: List[str]) -> List[str]:
    """
    List all files with specific extensions in a directory
    """
    try:
        files = []
        for ext in extensions:
            # Ensure the extension starts with a dot
            if not ext.startswith('.'):
                ext = f".{ext}"
            
            # Find all files with this extension
            for file_path in Path(directory_path).glob(f"*{ext}"):
                files.append(str(file_path))
        
        return files
    except Exception as e:
        logger.error(f"Error listing files by extension: {str(e)}")
        return []


def is_file_empty(file_path: str) -> bool:
    """
    Check if a file is empty
    """
    try:
        return os.path.getsize(file_path) == 0
    except Exception as e:
        logger.error(f"Error checking if file is empty: {str(e)}")
        return True  # Assume empty if there's an error


def schedule_file_cleanup():
    """
    Schedule regular cleanup of temporary and report files
    """
    try:
        # Clean up uploads and reports directories
        uploads_cleaned = clean_old_files(settings.UPLOAD_DIR, max_age_hours=settings.CLEANUP_AGE_HOURS)
        reports_cleaned = clean_old_files(settings.REPORTS_DIR, max_age_hours=settings.CLEANUP_AGE_HOURS)
        
        logger.info(f"Cleaned up {uploads_cleaned} old upload files and {reports_cleaned} old report files")
        
        # Schedule next cleanup
        # In a real application, this would use a task scheduler like Celery
        # For this example, we're just logging the intention
        logger.info(f"Next cleanup scheduled in {settings.CLEANUP_INTERVAL_HOURS} hours")
        
    except Exception as e:
        logger.error(f"Error in scheduled file cleanup: {str(e)}")