from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, BackgroundTasks, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional, List
import logging
import os
import uuid
from datetime import datetime, timedelta

from app.models.schemas import (
    Token, UserCreate, User, FileUploadResponse, AnalysisStatusResponse,
    AnalysisResult, AnalysisRequest, FileType, HealthCheck
)
from app.core.config import settings
from app.core.security import (
    create_access_token, verify_token, validate_file_type, 
    save_upload_file, compute_file_hash, rate_limit_check
)
from app.services.analyzer import analyze_file_task, get_analysis_status
from app.services.report_generator import generate_report

logger = logging.getLogger(__name__)
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Authentication routes
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # This is a simplified example - in production you would check against a database
    # For this example, we'll use a hardcoded user
    if form_data.username != "admin" or form_data.password != "password":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username, "permissions": ["admin"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# File upload and analysis routes
@router.post("/files/upload", response_model=FileUploadResponse)
async def upload_file(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_type: str = Form("full"),
):
    # Check rate limit
    client_ip = request.client.host
    if not rate_limit_check(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    # Validate file size
    if file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {settings.MAX_UPLOAD_SIZE/1024/1024} MB"
        )
    
    try:
        # Validate file type
        file_mime_type = validate_file_type(file)
        
        # Determine file type (exe or pdf)
        extension = file.filename.split(".")[-1].lower()
        file_type = FileType.EXE if extension == "exe" else FileType.PDF
        
        # Save file
        file_path = save_upload_file(file, file_type)
        
        # Generate file ID and task ID
        file_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        
        # Compute file hashes
        file_hashes = compute_file_hash(file_path)
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Create file info record
        file_info = {
            "file_id": file_id,
            "original_filename": file.filename,
            "file_path": file_path,
            "file_type": file_type,
            "file_size": file_size,
            "upload_time": datetime.utcnow(),
            "md5": file_hashes["md5"],
            "sha1": file_hashes["sha1"],
            "sha256": file_hashes["sha256"],
            "mime_type": file_mime_type,
        }
        
        # In a real application, save file_info to database
        
        # Start background analysis task
        background_tasks.add_task(
            analyze_file_task,
            file_id=file_id,
            task_id=task_id,
            file_path=file_path,
            file_type=file_type,
            file_info=file_info,
            analysis_type=analysis_type
        )
        
        return FileUploadResponse(
            file_id=file_id,
            filename=file.filename,
            file_type=file_type,
            file_size=file_size,
            upload_time=datetime.utcnow(),
            status="processing",
            task_id=task_id
        )
        
    except HTTPException as e:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing file upload: {str(e)}"
        )


@router.get("/analysis/{task_id}/status", response_model=AnalysisStatusResponse)
async def check_analysis_status(
    task_id: str,
    request: Request,  # Add this parameter
):
    """
    Check the status of an analysis task
    """
    status_data = get_analysis_status(task_id)
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis task with ID {task_id} not found"
        )
    
    # If result_url is a relative URL, convert it to absolute
    if status_data.get("result_url") and status_data["result_url"].startswith("/"):
        base_url = str(request.base_url).rstrip("/")
        status_data["result_url"] = f"{base_url}{status_data['result_url']}"
    
    return status_data


@router.get("/analysis/{task_id}/result", response_model=AnalysisResult)
async def get_analysis_result(
    task_id: str,
):
    """
    Get the results of a completed analysis
    """
    # In a real application, retrieve result from database
    # This is a placeholder implementation
    
    status_data = get_analysis_status(task_id)
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis task with ID {task_id} not found"
        )
    
    if status_data["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis task is not completed yet. Current status: {status_data['status']}"
        )
    
    # In a real application, retrieve the complete result from database
    # For this example, we'll return a simplified result
    
    return AnalysisResult(
        id=str(uuid.uuid4()),
        file_id=status_data["file_id"],
        task_id=task_id,
        status="completed",
        completed_at=datetime.utcnow(),
        # Details would come from database in real application
        details=None,
        report_path=f"/api/reports/{task_id}"
    )


@router.get("/reports/{task_id}")
async def get_report(
    task_id: str,
    format: str = "pdf",
):
    """
    Get the generated report file for an analysis
    """
    # Check if report exists
    report_filename = f"{task_id}.{format}"
    report_path = os.path.join(settings.REPORTS_DIR, report_filename)
    
    if not os.path.exists(report_path):
        # Generate report if it doesn't exist
        try:
            generate_report(task_id, format)
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error generating report: {str(e)}"
            )
    
    if not os.path.exists(report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found for task ID {task_id}"
        )
    
    # Determine content type
    content_type = "application/pdf" if format == "pdf" else "application/json" if format == "json" else "text/html"
    
    return FileResponse(
        path=report_path,
        filename=report_filename,
        media_type=content_type
    )


@router.post("/analysis/request", response_model=AnalysisStatusResponse)
async def request_analysis(
    analysis_request: AnalysisRequest,
    background_tasks: BackgroundTasks,
):
    """
    Request analysis of a previously uploaded file
    """
    # In a real application, check if file exists in database
    # For this example, we'll assume it exists
    
    file_id = analysis_request.file_id
    task_id = str(uuid.uuid4())
    
    # Start background analysis task
    # In a real application, retrieve file info from database
    background_tasks.add_task(
        analyze_file_task,
        file_id=file_id,
        task_id=task_id,
        file_path=None,  # Would retrieve from database
        file_type=None,  # Would retrieve from database
        file_info=None,  # Would retrieve from database
        analysis_type=analysis_request.analysis_type,
        priority=analysis_request.priority,
        callback_url=analysis_request.callback_url
    )
    
    return AnalysisStatusResponse(
        file_id=file_id,
        task_id=task_id,
        status="queued",
        progress=0.0
    )


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """
    Health check endpoint
    """
    return HealthCheck(
        status="ok",
        version="1.0.0"
    )