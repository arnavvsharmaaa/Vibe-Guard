import os
import uuid
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Vibe Guard API",
    description="Backend API for Vibe Guard - AI-Powered Secure Code Auditor",
    version="0.1.0",
)

# Upload directory configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Maximum upload size limit (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Allowed file extensions for source code and config files
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".css", ".json", ".sql",
    ".java", ".c", ".cpp", ".h", ".hpp", ".cs",
    ".go", ".rs", ".php", ".rb", ".sh", ".bash",
    ".yml", ".yaml", ".xml", ".toml", ".txt", ".md",
    ".zip", ".tar", ".gz",
}

# CORS configuration to allow local React development server
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

extra_origins = os.getenv("ALLOWED_ORIGINS")
if extra_origins:
    origins.extend([origin.strip() for origin in extra_origins.split(",") if origin.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "ok"}


@app.post("/api/scan/upload", tags=["Scan"])
async def upload_code_file(file: UploadFile = File(...)):
    """
    Accepts source-code files and stores them safely for the scanning pipeline.
    Validates file extension and size, preventing path traversal and execution.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    # Sanitize user filename to prevent path traversal
    safe_basename = Path(file.filename).name
    ext = Path(safe_basename).suffix.lower()

    if not ext or ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # Generate server-side unique ID
    file_id = uuid.uuid4().hex
    stored_filename = f"{file_id}_{safe_basename}"
    destination_path = (UPLOAD_DIR / stored_filename).resolve()

    # Ensure destination is strictly inside UPLOAD_DIR
    if not str(destination_path).startswith(str(UPLOAD_DIR.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file path",
        )

    # Stream file to disk and enforce size limit
    total_size = 0
    chunk_size = 64 * 1024  # 64 KB

    try:
        with open(destination_path, "wb") as buffer:
            while chunk := await file.read(chunk_size):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    buffer.close()
                    if destination_path.exists():
                        destination_path.unlink()
                    raise HTTPException(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        detail=f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE // (1024 * 1024)}MB",
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if destination_path.exists():
            destination_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file",
        )
    finally:
        await file.close()

    return {
        "status": "uploaded",
        "file_id": file_id,
        "filename": safe_basename,
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
