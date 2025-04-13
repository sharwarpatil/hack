import logging
import os
import uuid
from datetime import datetime


from app.core.config import settings


from app.core.security import (
    compute_file_hash,
    create_access_token,
    rate_limit_check,
    save_upload_file,
    validate_file_type,
)


from app.models.schemas import (
    AnalysisRequest,
    AnalysisResult,
    AnalysisStatusResponse,
    FileType,
    FileUploadResponse,
    HealthCheck,
)


from app.services.analyzer import analyze_file_task, get_analysis_status

from app.services.report_generator import generate_report


from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)


from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.responses import FileResponse


logger = logging.getLogger(__name__)

router = APIRouter()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.post("/token")
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
        expires_delta=access_token_expires,
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
    client_ip = request.client.host
    if not rate_limit_check(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
        )
    if file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {settings.MAX_UPLOAD_SIZE/1024/1024} MB",
        )
    try:
        file_mime_type = validate_file_type(file)
        extension = file.filename.split(".")[-1].lower()
        file_type = FileType.EXE if extension == "exe" else FileType.PDF

        file_path = save_upload_file(file, file_type)
        file_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        file_hashes = compute_file_hash(file_path)
        file_size = os.path.getsize(file_path)

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

        background_tasks.add_task(
            analyze_file_task,
            file_id=file_id,
            task_id=task_id,
            file_path=file_path,
            file_type=file_type,
            file_info=file_info,
            analysis_type=analysis_type,
        )

        return FileUploadResponse(
            file_id=file_id,
            filename=file.filename,
            file_type=file_type,
            file_size=file_size,
            upload_time=datetime.utcnow(),
            status="processing",
            task_id=task_id,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error('Error processing file upload: {}', str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing file upload: {str(e)}",
        )



@router.get("/analysis/{task_id}/status", response_model=AnalysisStatusResponse)
async def check_analysis_status(task_id: str):
    """
    Check the status of an analysis task
    """
    logger.info('Checking status for task ID: {}', task_id)
    status_data = get_analysis_status(task_id)
    logger.info('Status data: {}', status_data)
    
    if not status_data:
        logger.warning('Analysis task with ID {} not found', task_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis task with ID {task_id} not found",
        )
    return status_data



@router.get("/analysis/{task_id}/result", response_model=AnalysisResult)
async def get_analysis_result(
    task_id: str,
):
    status_data = get_analysis_status(task_id)
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis task with ID {task_id} not found",
        )
    if status_data["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis task is not completed yet. Current status: {status_data['status']}",
        )
    return AnalysisResult(
        id=str(uuid.uuid4()),
        file_id=status_data["file_id"],
        task_id=task_id,
        status="completed",
        completed_at=datetime.utcnow(),
        details=None,
        report_path=f"/api/reports/{task_id}",
    )


@router.get("/reports/{task_id}")
async def get_report(
    task_id: str,
    format: str = "pdf",
):
    report_filename = f"{task_id}.{format}"
    report_path = os.path.join(settings.REPORTS_DIR, report_filename)

    if not os.path.exists(report_path):
        try:
            generate_report(task_id, format)
        except Exception as e:
            logger.error('Error generating report: {}', str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error generating report: {str(e)}",
            )
    if not os.path.exists(report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Report not found for task ID {task_id}"
        )
    content_type_map = {
        "pdf": "application/pdf",
        "json": "application/json",
        "html": "text/html",
        "exe": "application/vnd.microsoft.portable-executable",
    }

    content_type = content_type_map.get(format.lower(), "application/octet-stream")
    return FileResponse(path=report_path, filename=report_filename, media_type=content_type)



@router.post("/analysis/dynamic", response_model=AnalysisStatusResponse)
async def request_dynamic_analysis(
    file_id: str = Form(...), 
):
    """
    Request dynamic analysis for a previously uploaded file
    """
    # Generate a new task ID

    task_id = str(uuid.uuid4())
    
    # Get file information (you'd retrieve this from your database)

    file_info = get_file_info(file_id)
    if not file_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"File with ID {file_id} not found"
        )
    # Start background task

    background_tasks.add_task(
        analyze_file_task,
        file_id=file_id,
        task_id=task_id,
        file_path=file_info["file_path"],
        file_type=file_info["file_type"],
        file_info=file_info,
        analysis_type="dynamic",
    )

    return AnalysisStatusResponse(file_id=file_id, task_id=task_id, status="queued", progress=0.0)


@router.post("/analysis/request", response_model=AnalysisStatusResponse)
async def request_analysis(
    analysis_request: AnalysisRequest,
    background_tasks: BackgroundTasks,
):
    file_id = analysis_request.file_id
    task_id = str(uuid.uuid4())

    background_tasks.add_task(
        analyze_file_task,
        file_id=file_id,
        task_id=task_id,
        file_path=None,
        file_type=None,
        file_info=None,
        analysis_type=analysis_request.analysis_type,
        priority=analysis_request.priority,
        callback_url=analysis_request.callback_url,
    )

    return AnalysisStatusResponse(file_id=file_id, task_id=task_id, status="queued", progress=0.0)


@router.get("/health", response_model=HealthCheck)
async def health_check():
    return HealthCheck(status="ok", version="1.0.0")