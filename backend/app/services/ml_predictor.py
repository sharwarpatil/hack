import logging
import os
import pickle
import hashlib
import json
import numpy as np
from typing import Dict, Any, List, Optional, Union
from sklearn.ensemble import RandomForestClassifier
import joblib
from datetime import datetime

from app.core.config import settings
from app.models.schemas import FileType, MalwareCategory, SeverityLevel
from app.services.exe_analyzer import check_exe_anomalies
from app.services.pdf_analyzer import check_pdf_anomalies
from app.utils.feature_extraction import extract_features_from_analysis

logger = logging.getLogger(__name__)

# Cache for loaded model
_model_cache = {
    "model": None,
    "loaded_at": None,
    "model_path": None
}


def load_model():
    """
    Load the pre-trained ML model from file
    """
    model_path = settings.MODEL_PATH
    
    # Check if model already loaded
    if (_model_cache["model"] is not None and 
        _model_cache["model_path"] == model_path and
        _model_cache["loaded_at"] is not None and
        (datetime.utcnow() - _model_cache["loaded_at"]).total_seconds() < 3600):
        # Return cached model if loaded within the last hour
        return _model_cache["model"]
    
    try:
        # Try different loading methods
        try:
            # Try joblib first (recommended for sklearn models)
            model = joblib.load(model_path)
            logger.info(f"Model loaded with joblib from {model_path}")
        except:
            # Fall back to pickle
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"Model loaded with pickle from {model_path}")
        
        # Update cache
        _model_cache["model"] = model
        _model_cache["loaded_at"] = datetime.utcnow()
        _model_cache["model_path"] = model_path
        
        return model
    
    except Exception as e:
        logger.error(f"Error loading model from {model_path}: {str(e)}")
        
        # Create and return a fallback model for development/testing
        logger.warning("Using fallback model for prediction")
        fallback_model = create_fallback_model()
        _model_cache["model"] = fallback_model
        _model_cache["loaded_at"] = datetime.utcnow()
        _model_cache["model_path"] = "fallback"
        
        return fallback_model


def create_fallback_model():
    """
    Create a simple fallback model for development/testing
    This will be used if the real model can't be loaded
    """
    model = FallbackMalwarePredictor()
    return model


class FallbackMalwarePredictor:
    """
    Simple rule-based predictor to use when the ML model is not available
    """
    def __init__(self):
        self.name = "Fallback Rule-based Predictor"
    
    def predict_proba(self, X):
        """
        Make probability predictions based on simple rules
        """
        # In a real scenario, we'd use the ML model
        # This is just a placeholder that looks at the features
        
        results = []
        for features in X:
            # Convert features to a dictionary for easier access
            if isinstance(features, np.ndarray):
                # Assume it's a simple array with handcrafted features
                # Just use position as a heuristic
                score = min(0.95, max(0.05, features[0]))
            elif isinstance(features, dict):
                # If we have named features
                has_signatures = features.get('has_malware_signatures', 0)
                has_packing = features.get('is_packed', 0)
                has_strange_sections = features.get('has_unusual_sections', 0)
                has_suspicious_imports = features.get('suspicious_import_count', 0)
                entropy = features.get('avg_section_entropy', 0)
                
                base_score = 0.1
                if has_signatures:
                    base_score += 0.5
                if has_packing:
                    base_score += 0.2
                if has_strange_sections:
                    base_score += 0.1
                if has_suspicious_imports > 5:
                    base_score += 0.2
                if entropy > 6.5:
                    base_score += 0.1
                    
                score = min(0.95, base_score)
            else:
                # Default score if we can't determine
                score = 0.5
            
            # Return probabilities for [benign, malware]
            results.append([1 - score, score])
        
        return np.array(results)


def map_score_to_severity(score: float) -> SeverityLevel:
    """
    Map malware score to severity level
    """
    if score < 0.2:
        return SeverityLevel.CLEAN
    elif score < 0.5:
        return SeverityLevel.LOW
    elif score < 0.8:
        return SeverityLevel.MEDIUM
    else:
        return SeverityLevel.HIGH


def map_score_to_category(score: float, file_type: FileType, analysis_data: Dict[str, Any]) -> MalwareCategory:
    """
    Map malware score and file analysis data to malware category
    """
    if score < 0.2:
        return MalwareCategory.CLEAN
    
    # Look for patterns in the analysis data to determine category
    # These are simplified rules - a real ML model would be more sophisticated
    
    if file_type == FileType.EXE:
        # Check imports for patterns
        imports = analysis_data.get("imports", [])
        import_str = " ".join(imports).lower()
        
        # Check for ransomware indicators
        if any(keyword in import_str for keyword in ["crypt", "encrypt", "ransom", "bitcoin", "payment"]):
            return MalwareCategory.RANSOMWARE
            
        # Check for keylogger/spyware indicators
        if any(keyword in import_str for keyword in ["keyboard", "hook", "getasynckeystate", "getforegroundwindow"]):
            return MalwareCategory.SPYWARE
            
        # Check for botnet indicators
        if any(keyword in import_str for keyword in ["socket", "connect", "wsastartup", "irc", "recv", "send"]):
            return MalwareCategory.BOTNET
            
        # Check for backdoor indicators
        if any(keyword in import_str for keyword in ["shell", "createprocess", "command", "exec", "system"]):
            return MalwareCategory.BACKDOOR
            
        # Check for rootkit indicators
        if any(keyword in import_str for keyword in ["ntdll", "driver", "kernel", "ntcreatefile"]):
            return MalwareCategory.ROOTKIT
            
        # Default to trojan for high-confidence malware
        if score > 0.8:
            return MalwareCategory.TROJAN
        
        # Fall back to unknown category
        return MalwareCategory.UNKNOWN
        
    elif file_type == FileType.PDF:
        # Determine PDF malware category
        if analysis_data.get("has_javascript", False):
            # PDFs with JavaScript are often trojans
            return MalwareCategory.TROJAN
            
        if analysis_data.get("has_embedded_files", False):
            # PDFs with embedded files could be droppers
            return MalwareCategory.TROJAN
            
        if analysis_data.get("has_auto_action", False):
            # PDFs with auto actions could be exploits
            return MalwareCategory.BACKDOOR
            
        # Default for high-confidence malware
        if score > 0.8:
            return MalwareCategory.TROJAN
        
        # Fall back to unknown category
        return MalwareCategory.UNKNOWN
    
    return MalwareCategory.UNKNOWN


def predict_malware(file_path: str, file_type: FileType, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict whether a file is malware using the pre-trained model
    """
    logger.info(f"Predicting malware status for {file_path}")
    
    try:
        # 1. Extract features from analysis data
        features = extract_features_from_analysis(file_type, analysis_data)
        
        # 2. Load the ML model
        model = load_model()
        
        # 3. Make prediction
        # Convert features to the format expected by the model
        feature_vector = np.array([list(features.values())])
        
        # Get probability scores [benign_prob, malware_prob]
        probabilities = model.predict_proba(feature_vector)
        malware_score = float(probabilities[0][1])  # Probability of being malware
        
        # 4. Determine confidence
        confidence = max(probabilities[0])  # Higher value indicates more confidence
        
        # 5. Determine severity level
        severity = map_score_to_severity(malware_score)
        
        # 6. Determine malware category
        category = map_score_to_category(malware_score, file_type, analysis_data)
        
        # 7. Get additional indicators based on file type
        indicators = []
        if file_type == FileType.EXE:
            indicators = check_exe_anomalies(analysis_data)
        elif file_type == FileType.PDF:
            indicators = check_pdf_anomalies(analysis_data)
        
        # 8. Generate summary
        summary = generate_analysis_summary(file_type, malware_score, severity, category, indicators)
        
        # 9. Format and return results
        result = {
            "malware_score": malware_score,
            "confidence": float(confidence),
            "severity": severity,
            "category": category,
            "indicators": indicators,
            "summary": summary,
            # Placeholder for malware family - would require a more sophisticated model
            "family": determine_malware_family(category, indicators, analysis_data)
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error predicting malware status: {str(e)}")
        # Return a safe default
        return {
            "malware_score": 0.5,  # Inconclusive
            "confidence": 0.0,     # No confidence
            "severity": SeverityLevel.UNKNOWN,
            "category": MalwareCategory.UNKNOWN,
            "indicators": [{
                "type": "error",
                "name": "Prediction Error",
                "description": f"Error during malware prediction: {str(e)}",
                "severity": "medium"
            }],
            "summary": f"Error during analysis: {str(e)}",
            "family": None
        }


def generate_analysis_summary(
    file_type: FileType,
    malware_score: float,
    severity: SeverityLevel,
    category: MalwareCategory,
    indicators: List[Dict[str, Any]]
) -> str:
    """
    Generate a human-readable summary of the analysis results
    """
    file_type_str = "executable" if file_type == FileType.EXE else "PDF document"
    
    if malware_score < 0.2:
        base_summary = f"This {file_type_str} appears to be clean with a low malware score of {malware_score:.2f}."
        if indicators:
            return f"{base_summary} However, {len(indicators)} potential indicators were identified that should be reviewed."
        return f"{base_summary} No significant security indicators were found."
    
    elif malware_score < 0.5:
        base_summary = f"This {file_type_str} has a low-to-moderate malware score of {malware_score:.2f}, indicating some suspicion."
        indicator_types = [ind["type"] for ind in indicators]
        indicator_summary = ", ".join(list(set(indicator_types))[:3])
        return f"{base_summary} Analysis detected {len(indicators)} potential indicators including {indicator_summary}."
    
    elif malware_score < 0.8:
        base_summary = f"This {file_type_str} has a high malware score of {malware_score:.2f} with {severity} severity."
        indicator_summary = ""
        high_severity_indicators = [ind for ind in indicators if ind.get("severity") in ["high", "critical"]]
        if high_severity_indicators:
            high_sev_names = [ind["name"] for ind in high_severity_indicators][:3]
            indicator_summary = f" High severity indicators include {', '.join(high_sev_names)}."
        return f"{base_summary} The sample was classified as potential {category}.{indicator_summary}"
    
    else:
        base_summary = f"This {file_type_str} has a very high malware score of {malware_score:.2f} with {severity} severity."
        indicator_summary = ""
        critical_indicators = [ind for ind in indicators if ind.get("severity") == "critical"]
        if critical_indicators:
            critical_names = [ind["name"] for ind in critical_indicators][:3]
            indicator_summary = f" Critical indicators include {', '.join(critical_names)}."
        return f"{base_summary} The sample was classified as {category} malware with high confidence.{indicator_summary}"


def determine_malware_family(
    category: MalwareCategory,
    indicators: List[Dict[str, Any]],
    analysis_data: Dict[str, Any]
) -> Optional[str]:
    """
    Attempt to determine the malware family based on indicators and analysis data
    This is a simplified implementation - a real system would use more sophisticated techniques
    """
    # If it's clean, no family
    if category == MalwareCategory.CLEAN or category == MalwareCategory.UNKNOWN:
        return None
    
    # Look for specific patterns in the analysis data and indicators
    
    # Example logic for some common malware families
    # This would be much more sophisticated in a real system
    
    # Check for Emotet indicators
    emotet_patterns = [
        "powershell -e",
        "regsvr32",
        "mshta.exe",
        "office macro",
        "emotet"
    ]
    
    # Check for Trickbot indicators
    trickbot_patterns = [
        "systeminfo",
        "resource 64",
        "trickbot",
        "C:\\Users\\Public\\",
        "netsh firewall"
    ]
    
    # Check for WannaCry indicators
    wannacry_patterns = [
        "mssecsvc.exe",
        "tasksche.exe",
        "wcry",
        "wannacry",
        "wanna decryptor"
    ]
    
    # Check for strings in all relevant parts of the analysis
    all_strings = []
    
    # Add strings from indicators
    for indicator in indicators:
        all_strings.append(indicator.get("name", "").lower())
        all_strings.append(indicator.get("description", "").lower())
    
    # Add strings from analysis_data based on file type
    if "exe_details" in analysis_data:
        # Add strings from EXE analysis
        for import_name in analysis_data.get("exe_details", {}).get("imports", []):
            all_strings.append(import_name.lower())
        
        for string_obj in analysis_data.get("exe_details", {}).get("strings_of_interest", []):
            if isinstance(string_obj, dict) and "value" in string_obj:
                all_strings.append(string_obj["value"].lower())
            elif isinstance(string_obj, str):
                all_strings.append(string_obj.lower())
    
    elif "pdf_details" in analysis_data:
        # Add strings from PDF analysis
        for js_code in analysis_data.get("pdf_details", {}).get("javascript_code", []):
            all_strings.append(js_code.lower())
        
        for url in analysis_data.get("pdf_details", {}).get("urls", []):
            all_strings.append(url.lower())
    
    # Join all strings for easier searching
    all_text = " ".join(all_strings)
    
    # Check for known families
    if any(pattern.lower() in all_text for pattern in emotet_patterns):
        return "Emotet"
    elif any(pattern.lower() in all_text for pattern in trickbot_patterns):
        return "Trickbot"
    elif any(pattern.lower() in all_text for pattern in wannacry_patterns):
        return "WannaCry"
    
    # More families could be added here
    
    # Default to None if no family can be determined
    return None