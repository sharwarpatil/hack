import logging
import math
import hashlib
import re
import numpy as np
from typing import Dict, Any, List, Set, Optional
import statistics
from collections import Counter

from app.models.schemas import FileType

logger = logging.getLogger(__name__)

# Known suspicious API calls for EXE files
SUSPICIOUS_API_CALLS = {
    "network": [
        "internetopen", "internetopenurl", "internetreadfile", "internetwritefile",
        "urldownloadtofile", "httpopenrequest", "httpsendrequest", "wsastartup",
        "socket", "connect", "recv", "send", "bind", "listen", "accept"
    ],
    "process": [
        "createprocess", "virtualalloc", "virtualprotect", "writeprocessmemory",
        "createremotethread", "openprocess", "terminateprocess", "exitprocess",
        "createthread", "ntcreatethreadex", "queueuserapc"
    ],
    "registry": [
        "regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue",
        "regdeletekey", "regenumkey", "regsavekey"
    ],
    "file": [
        "createfile", "writefile", "readfile", "deletefile", "copyfile",
        "movefile", "setfileattributes", "gettemppath", "gettempfilename"
    ],
    "system": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
        "gettickcount", "getsystemtime", "getversionex", "getcomputername",
        "getusername", "getsystemdirectory", "getwindowsdirectory"
    ],
    "crypto": [
        "cryptacquirecontext", "cryptcreatehash", "crypthashdata", "cryptderivekey",
        "cryptencrypt", "cryptdecrypt", "cryptgenrandom"
    ],
    "keylogging": [
        "setwindowshookex", "getasynckeystate", "getkeystate", "getkeyboardstate",
        "registerhotkey", "getmessage", "peekmessage"
    ],
    "injection": [
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntmapviewofsection", "zwmapviewofsection", "setthreadcontext"
    ]
}

# Known suspicious patterns for PDF files
SUSPICIOUS_PDF_PATTERNS = [
    "javascript", "js", "eval", "unescape", "fromcharcode", "activex",
    "shellcode", "exploit", "payload", "vulnerability", "obfuscate",
    "encrypt", "crypt", "URI", "URL", "openaction", "launch", "submit"
]


def extract_features_from_analysis(file_type: FileType, analysis_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract numerical features from file analysis data for ML prediction
    """
    if file_type == FileType.EXE:
        return extract_exe_features(analysis_data)
    elif file_type == FileType.PDF:
        return extract_pdf_features(analysis_data)
    else:
        logger.warning(f"Unsupported file type for feature extraction: {file_type}")
        return {}


def extract_exe_features(analysis_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract features from EXE analysis data
    """
    features = {}
    
    try:
        # Basic features
        features["is_dll"] = 1.0 if analysis_data.get("is_dll", False) else 0.0
        features["is_driver"] = 1.0 if analysis_data.get("is_driver", False) else 0.0
        features["is_packed"] = 1.0 if analysis_data.get("is_packed", False) else 0.0
        
        # Section features
        sections = analysis_data.get("sections", [])
        if sections:
            section_entropies = [section.get("entropy", 0) for section in sections]
            features["section_count"] = float(len(sections))
            features["avg_section_entropy"] = float(sum(section_entropies) / len(sections)) if section_entropies else 0.0
            features["max_section_entropy"] = float(max(section_entropies)) if section_entropies else 0.0
            
            # Count sections with suspicious characteristics
            executable_writable_count = sum(
                1 for section in sections
                if "MEM_EXECUTE" in section.get("characteristics", []) and "MEM_WRITE" in section.get("characteristics", [])
            )
            features["executable_writable_sections"] = float(executable_writable_count)
            
            # Check for anomalous section names
            normal_section_names = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata", ".pdata"}
            abnormal_section_names = sum(1 for section in sections if section.get("name", "") not in normal_section_names)
            features["abnormal_section_names"] = float(abnormal_section_names)
        else:
            features["section_count"] = 0.0
            features["avg_section_entropy"] = 0.0
            features["max_section_entropy"] = 0.0
            features["executable_writable_sections"] = 0.0
            features["abnormal_section_names"] = 0.0
        
        # Import features
        imports = analysis_data.get("imports", [])
        libraries = analysis_data.get("libraries", [])
        
        features["import_count"] = float(len(imports))
        features["library_count"] = float(len(libraries))
        
        # Count suspicious API calls by category
        for category, api_list in SUSPICIOUS_API_CALLS.items():
            category_count = 0
            for import_name in imports:
                if any(api.lower() in import_name.lower() for api in api_list):
                    category_count += 1
            features[f"suspicious_{category}_apis"] = float(category_count)
        
        # Aggregate suspicious APIs
        features["suspicious_import_count"] = sum(
            features[f"suspicious_{category}_apis"]
            for category in SUSPICIOUS_API_CALLS.keys()
        )
        
        # Resource features
        resources = analysis_data.get("resources", [])
        features["resource_count"] = float(len(resources))
        
        # String features
        strings_of_interest = analysis_data.get("strings_of_interest", [])
        url_count = 0
        ip_count = 0
        registry_count = 0
        file_path_count = 0
        api_count = 0
        
        for string_item in strings_of_interest:
            if isinstance(string_item, dict):
                string_type = string_item.get("type", "")
                if string_type == "url":
                    url_count += 1
                elif string_type == "ip":
                    ip_count += 1
                elif string_type == "registry":
                    registry_count += 1
                elif string_type == "file_path":
                    file_path_count += 1
                elif string_type == "api_calls":
                    api_count += 1
        
        features["url_string_count"] = float(url_count)
        features["ip_string_count"] = float(ip_count)
        features["registry_string_count"] = float(registry_count)
        features["file_path_string_count"] = float(file_path_count)
        features["api_string_count"] = float(api_count)
        features["total_interesting_strings"] = float(url_count + ip_count + registry_count + file_path_count + api_count)
        
        # Digital signature
        features["has_signature"] = 1.0 if analysis_data.get("digital_signature", {}) else 0.0
        
        # Timestamp features - convert to a normalized form
        compile_time = analysis_data.get("compile_time", None)
        features["has_timestamp"] = 1.0 if compile_time else 0.0
        
        # Has malware signatures - flag from more detailed analysis
        # This would be populated by a separate signature detection module
        features["has_malware_signatures"] = 0.0  # Placeholder
        
        # Check for known malware imports (simplified)
        known_malware_imports = ["createfilemapping", "mapviewoffile", "setthreadcontext", "createservice"]
        has_malware_imports = 0
        for import_name in imports:
            if any(malware_import.lower() in import_name.lower() for malware_import in known_malware_imports):
                has_malware_imports = 1
                break
        features["has_malware_imports"] = float(has_malware_imports)
        
        # Additional binary properties
        features["has_tls"] = 1.0 if "IMAGE_DIRECTORY_ENTRY_TLS" in str(analysis_data.get("pe_characteristics", {})) else 0.0
        features["is_gui"] = 1.0 if analysis_data.get("subsystem", "") == "Windows GUI" else 0.0
        
        # Mark if has unusual sections based on entropy and other factors
        has_unusual_sections = 0
        if features["max_section_entropy"] > 7.5 or features["executable_writable_sections"] > 0 or features["abnormal_section_names"] > 1:
            has_unusual_sections = 1
        features["has_unusual_sections"] = float(has_unusual_sections)
        
    except Exception as e:
        logger.error(f"Error extracting EXE features: {str(e)}")
        # Provide default values for critical features
        features["section_count"] = 0.0
        features["import_count"] = 0.0
        features["suspicious_import_count"] = 0.0
        features["has_malware_signatures"] = 0.0
    
    return features


def extract_pdf_features(analysis_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract features from PDF analysis data
    """
    features = {}
    
    try:
        # Basic features
        features["page_count"] = float(analysis_data.get("page_count", 0))
        features["has_javascript"] = 1.0 if analysis_data.get("has_javascript", False) else 0.0
        features["has_forms"] = 1.0 if analysis_data.get("has_forms", False) else 0.0
        features["has_embedded_files"] = 1.0 if analysis_data.get("has_embedded_files", False) else 0.0
        features["has_auto_action"] = 1.0 if analysis_data.get("has_auto_action", False) else 0.0
        features["has_suspicious_objects"] = 1.0 if analysis_data.get("has_suspicious_objects", False) else 0.0
        features["has_encryption"] = 1.0 if analysis_data.get("has_encryption", False) else 0.0
        features["has_obfuscation"] = 1.0 if analysis_data.get("has_obfuscation", False) else 0.0
        
        # Count embedded files
        embedded_files = analysis_data.get("embedded_files", [])
        features["embedded_file_count"] = float(len(embedded_files))
        
        # Count suspicious objects
        suspicious_objects = analysis_data.get("suspicious_objects", [])
        features["suspicious_object_count"] = float(len(suspicious_objects))
        
        # Categorize suspicious objects
        suspicious_js_count = sum(1 for obj in suspicious_objects if obj.get("type", "") == "javascript")
        suspicious_execution_count = sum(1 for obj in suspicious_objects if obj.get("type", "") == "execution")
        suspicious_uri_count = sum(1 for obj in suspicious_objects if obj.get("type", "") == "uri")
        suspicious_action_count = sum(1 for obj in suspicious_objects if obj.get("type", "") == "action")
        suspicious_embedding_count = sum(1 for obj in suspicious_objects if obj.get("type", "") == "embedding")
        
        features["suspicious_js_count"] = float(suspicious_js_count)
        features["suspicious_execution_count"] = float(suspicious_execution_count)
        features["suspicious_uri_count"] = float(suspicious_uri_count)
        features["suspicious_action_count"] = float(suspicious_action_count)
        features["suspicious_embedding_count"] = float(suspicious_embedding_count)
        
        # Count auto actions
        auto_actions = analysis_data.get("auto_actions", [])
        features["auto_action_count"] = float(len(auto_actions))
        
        # Count URLs
        urls = analysis_data.get("urls", [])
        features["url_count"] = float(len(urls))
        
        # Count suspicious URLs (simplified)
        suspicious_url_count = sum(
            1 for url in urls
            if any(pattern in url.lower() for pattern in ["bit.ly", "tinyurl", "goo.gl", "pastebin", "t.co"])
        )
        features["suspicious_url_count"] = float(suspicious_url_count)
        
        # JavaScript analysis
        js_code = analysis_data.get("javascript_code", [])
        js_code_str = " ".join(js_code).lower()
        
        # Count suspicious JavaScript patterns
        js_eval_count = js_code_str.count("eval(")
        js_unescape_count = js_code_str.count("unescape(")
        js_fromcharcode_count = js_code_str.count("fromcharcode")
        js_suspicious_patterns = sum(js_code_str.count(pattern.lower()) for pattern in SUSPICIOUS_PDF_PATTERNS)
        
        features["js_eval_count"] = float(js_eval_count)
        features["js_unescape_count"] = float(js_unescape_count)
        features["js_fromcharcode_count"] = float(js_fromcharcode_count)
        features["js_suspicious_patterns"] = float(js_suspicious_patterns)
        
        # Check for known exploit patterns
        known_exploit_patterns = [
            "colladadata", "u3d", "geticon", "media.newplayer", "spell.customdictionaryopen",
            "util.printf", "getannots", "app.setinterval", "app.settimeout"
        ]
        
        has_known_exploits = 0
        for pattern in known_exploit_patterns:
            if pattern in js_code_str:
                has_known_exploits = 1
                break
        
        features["has_known_exploits"] = float(has_known_exploits)
        
        # Additional characteristics
        features["has_acroform"] = 1.0 if analysis_data.get("acroform_fields", []) else 0.0
        features["has_xfa_form"] = 1.0 if analysis_data.get("xfa_forms", []) else 0.0
        
        # Has malware signatures - flag from detailed analysis
        features["has_malware_signatures"] = 0.0  # Placeholder
        
    except Exception as e:
        logger.error(f"Error extracting PDF features: {str(e)}")
        # Provide default values for critical features
        features["has_javascript"] = 0.0
        features["has_auto_action"] = 0.0
        features["has_embedded_files"] = 0.0
        features["has_malware_signatures"] = 0.0
    
    return features