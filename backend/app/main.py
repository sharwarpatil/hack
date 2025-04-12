from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time
import uuid
from app.api.routes import router as api_router
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("app")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Static Malware Analysis API for EXE and PDF files",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Add request logging
    start_time = time.time()
    logger.info(f"Request started - ID: {request_id} - Path: {request.url.path}")
    
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        # Log request completion
        process_time = time.time() - start_time
        logger.info(f"Request completed - ID: {request_id} - Time: {process_time:.3f}s")
        
        return response
    except Exception as e:
        logger.error(f"Request failed - ID: {request_id} - Error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

# Include API routes
app.include_router(api_router, prefix="/api")

@app.get("/", tags=["Health"])
async def health_check():
    return {"status": "ok", "message": "Static Malware Analyzer API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)