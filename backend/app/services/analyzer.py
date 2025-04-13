import logging
from datetime import datetime, timedelta

from typing import Any, Dict, Optional

import requests


from app.core.config import settings
from app.models.schemas import FileType, MalwareCategory, SeverityLevel
from app.services.dynamic_analyzer import analyze_exe_dynamically
from app.services.exe_analyzer import analyze_exe
from app.services.ml_predictor import predict_malware
from app.services.pdf_analyzer import analyze_pdf

from app.services.report_generator import generate_report


logger = logging.getLogger(__name__)

# In-memory storage for analysis tasks (replace with database in production)
analysis_tasks = {}
analysis_results = {}


def update_analysis_status(
    task_id: str, status: str, progress: float = 0.0, result_url: Optional[str] = None
):
    """
    Update the status of an analysis task
    """
    if task_id in analysis_tasks:
        analysis_tasks[task_id].update({
            "status": status,
            "progress": progress,
            "last_updated": datetime.utcnow(),
            "result_url": result_url,
        })
        
        # If completed, estimate completion time based on progress and elapsed time

        if progress > 0 and progress < 1.0:
            start_time = analysis_tasks[task_id].get("start_time", datetime.utcnow())
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            estimated_remaining = (elapsed / progress) * (1.0 - progress)
            estimated_completion = datetime.utcnow() + timedelta(seconds=estimated_remaining)
            analysis_tasks[task_id]["estimated_completion_time"] = estimated_completion



def get_analysis_status(task_id: str) -> Optional[Dict[str, Any]]:
    """
    Get the current status of an analysis task
    """
    return analysis_tasks.get(task_id)


def get_recommendation(ml_results: Dict[str, Any]) -> str:
    """
    Generate recommendation based on malware analysis results
    """
    score = ml_results.get("malware_score", 0.0)
    severity = ml_results.get("severity", SeverityLevel.UNKNOWN)
    
    if severity == SeverityLevel.HIGH or score > 0.8:
        return "Highly suspicious file. Immediate quarantine recommended."
    if severity == SeverityLevel.MEDIUM or score > 0.5:
        return "Potentially malicious. Further investigation recommended."
    if severity == SeverityLevel.LOW or score > 0.3:
        return "Low risk file. Monitor for suspicious behavior."
    return "No significant threats detected. File appears to be safe."


def analyze_file_task(
    file_id: str,
    task_id: str,
    file_path: str,
    file_type: FileType,
    file_info: Dict[str, Any],
    analysis_type: str = "full",
    priority: str = "normal",
    callback_url: Optional[str] = None,
):
    """
    Background task that performs the analysis of a file
    """
    logger.info('Starting analysis task {} for file {}', task_id, file_id)
    
    # Register the task in the task registry

    analysis_tasks[task_id] = {
        "file_id": file_id,
        "task_id": task_id,
        "status": "starting",
        "progress": 0.0,
        "start_time": datetime.utcnow(),
        "estimated_completion_time": datetime.utcnow() + timedelta(minutes=5),
        "analysis_type": analysis_type,
        "priority": priority,
        "callback_url": callback_url,
        "result_url": None,
    }
    
    try:
        # Step 1: Update status to processing

        update_analysis_status(task_id, "processing", 0.1)
        
        # Step 2: Perform initial file analysis based on file type

        file_analysis_results = {}
        
        if file_type == FileType.EXE:
            file_analysis_results = analyze_exe(file_path)
        elif file_type == FileType.PDF:
            file_analysis_results = analyze_pdf(file_path)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
        update_analysis_status(task_id, "processing", 0.3)
        
        # Step 3: Run ML prediction

        ml_results = predict_malware(file_path, file_type, file_analysis_results)
        
        update_analysis_status(task_id, "processing", 0.5)
        
        # Step 4: Run dynamic analysis for EXE files if full analysis requested

        dynamic_analysis_results = None
        if (
            file_type == FileType.EXE
            and analysis_type == "full"
            and settings.ENABLE_DYNAMIC_ANALYSIS
        ):
            update_analysis_status(task_id, "processing", 0.6, "Running dynamic analysis...")
            dynamic_analysis_results = analyze_exe_dynamically(file_path)
            
            # Adjust ML results based on dynamic analysis

            if dynamic_analysis_results and "maliciousness_score" in dynamic_analysis_results:
                # Blend static and dynamic scores (giving more weight to dynamic)

                dynamic_score = dynamic_analysis_results["maliciousness_score"]
                static_score = ml_results.get("malware_score", 0.0)
                
                # New score is 40% static + 60% dynamic

                blended_score = (static_score * 0.4) + (dynamic_score * 0.6)
                ml_results["malware_score"] = blended_score
                
                # Adjust severity if dynamic analysis shows strong indicators

                if dynamic_score > 0.8 and ml_results.get("severity") != SeverityLevel.HIGH:
                    ml_results["severity"] = SeverityLevel.HIGH
                # Add dynamic suspicious behaviors to indicators

                if "suspicious_behaviors" in dynamic_analysis_results:
                    for behavior in dynamic_analysis_results["suspicious_behaviors"]:
                        ml_results.setdefault("indicators", []).append({
                            "name": behavior["type"],
                            "description": behavior["description"],
                            "severity": behavior["severity"],
                            "confidence": 0.9,  # High confidence for dynamic detections
                        })
        update_analysis_status(task_id, "processing", 0.7)
        
        # Step 5: Combine results and create final analysis

        analysis_result = {
            "file_info": file_info,
            "malware_score": ml_results.get("malware_score", 0.0),
            "malware_category": ml_results.get("category", MalwareCategory.UNKNOWN),
            "severity": ml_results.get("severity", SeverityLevel.UNKNOWN),
            "confidence": ml_results.get("confidence", 0.0),
            "analysis_time": datetime.utcnow(),
            "indicators": ml_results.get("indicators", []),
            "static_analysis_summary": ml_results.get("summary", ""),
            "malware_family": ml_results.get("family", None),
            "recommendation": get_recommendation(ml_results),
        }
        
        # Add file type specific details

        if file_type == FileType.EXE:
            analysis_result["exe_details"] = file_analysis_results
            if dynamic_analysis_results:
                analysis_result["dynamic_analysis"] = dynamic_analysis_results
        elif file_type == FileType.PDF:
            analysis_result["pdf_details"] = file_analysis_results
        update_analysis_status(task_id, "processing", 0.8)
        
        # Step 6: Generate report

        report_path = generate_report(task_id, "pdf", analysis_result)
        
        # Step 7: Store results (in a real application, save to database)

        analysis_results[task_id] = {"result": analysis_result, "report_path": report_path}

        # Step 8: Update status to completed

        result_url = f"/api/reports/{task_id}"
        update_analysis_status(task_id, "completed", 1.0, result_url)
        
        # Step 9: Send callback if provided

        if callback_url:
            try:
                requests.post(
                    callback_url,
                    json={
                        "task_id": task_id,
                        "file_id": file_id,
                        "status": "completed",
                        "result_url": result_url,
                    },
                    timeout=10,
                )
            except Exception as e:
                logger.error('Error sending callback to {}: {}', callback_url, str(e))
        logger.info('Analysis task {} completed successfully', task_id)
    except Exception as e:
        logger.error('Error in analysis task {}: {}', task_id, str(e))
        update_analysis_status(task_id, "failed", 0.0)
        
        # Send error callback if provided

        if callback_url:
            try:
                requests.post(
                    callback_url,
                    json={
                        "task_id": task_id,
                        "file_id": file_id,
                        "status": "failed",
                        "error": str(e),
                    },
                    timeout=10,
                )
            except Exception as callback_error:
                logger.error(
                    'Error sending error callback to {}: {}', callback_url, str(callback_error)
                )


# Update the recommendation function to include dynamic analysis insights
def get_recommendation(ml_results: Dict[str, Any]) -> str:
    """
    Generate a recommendation based on ML results and dynamic analysis
    """
    malware_score = ml_results.get("malware_score", 0.0)
    category = ml_results.get("category", MalwareCategory.UNKNOWN)
    severity = ml_results.get("severity", SeverityLevel.UNKNOWN)
    
    # Check if dynamic analysis was performed
    dynamic_analysis = ml_results.get("dynamic_analysis", None)
    dynamic_insights = ""
    
    if dynamic_analysis and "behavior_summary" in dynamic_analysis:
        dynamic_insights = f" Dynamic analysis shows: {dynamic_analysis['behavior_summary']}"
    
    if malware_score < 0.2:
        return f"This file appears to be safe based on our analysis. No action needed.{dynamic_insights}"
    if malware_score < 0.5:
        return f"This file has some suspicious characteristics but is likely not malicious. Exercise caution when using it.{dynamic_insights}"
    if malware_score < 0.8:
        return f"This file shows significant signs of being {category} malware with {severity} severity. We recommend not using this file and scanning your system for potential infections.{dynamic_insights}"
    return f"This file is highly likely to be {category} malware with {severity} severity. Do not use this file and immediately perform a full system scan with updated antivirus software.{dynamic_insights}"