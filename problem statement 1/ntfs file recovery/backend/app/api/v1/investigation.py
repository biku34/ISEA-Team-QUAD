"""
Investigation Management API endpoints.
Provides endpoints for resetting the investigation environment.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from loguru import logger

from app.database import get_db
from app.services.forensic_engine import ForensicEngine

router = APIRouter()
forensic_engine = ForensicEngine()

@router.post("/reset", status_code=status.HTTP_200_OK)
def reset_investigation(db: Session = Depends(get_db)):
    """
    Completely reset the forensic investigation environment.
    
    **CAUTION:** This operation will:
    1. Terminate all active Scalpel carving processes.
    2. Unmount all mounted evidence images.
    3. Drop all tables in the database and re-initialize them.
    4. Delete all tracked metadata.
    
    This is used to clean up the environment for a new investigation.
    """
    try:
        logger.warning("Reset investigation requested via API")
        results = forensic_engine.reset_investigation(db)
        
        return {
            "success": True,
            "message": "Investigation environment has been reset",
            "details": results
        }
    except Exception as e:
        logger.error(f"Reset investigation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reset failed: {str(e)}"
        )
