import logging
import os
import re
import json
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import tempfile
import subprocess
import hashlib

# Third-party libraries for PDF analysis
try:
    import PyPDF2
    from PyPDF2 import PdfReader
    from PyPDF2.errors import PdfReadError
except ImportError:
    logging.error("PyPDF2 not installed, PDF analysis will be limited")

# Try to import peepdf for more detailed PDF analysis
try:
    import peepdf
    from peepdf.PDFCore import PDFParser
    PEEPDF_AVAILABLE = True
except ImportError:
    PEEPDF_AVAILABLE = False
    logging.warning("peepdf not available, using limited PDF analysis")

from app.core.config import settings

logger = logging.getLogger(__name__)

# Suspicious PDF elements
SUSPICIOUS_PDF_ELEMENTS = {
    "javascript": ["/JS", "/JavaScript", "eval", "unescape", "String.fromCharCode"],
    "execution": ["app.launch", "app.setTimeOut", "app.setInterval", "app.execute"],
    "uri": ["/URI", "/URL", "/GoTo", "/GoToR", "/GoToE", "/Launch", "/SubmitForm", "/ImportData"],
    "action": ["/Action", "/AA", "/OpenAction", "/AcroForm", "/XFA"],
    "embedding": ["/EmbeddedFile", "/EmbeddedFiles", "/ObjStm", "/ObjRef"],
    "compression": ["/FlateDecode", "/ASCIIHexDecode", "/ASCII85Decode", "/LZWDecode", "/RunLengthDecode"],
    "font": ["/Font", "/Type0", "/Type1", "/TrueType", "/FontDescriptor", "/FontFile"],
    "encoding": ["/Encoding", "/Identity-H", "/Differences", "/ToUnicode"]
}

# Known PDF vulnerabilities by CVE
PDF_VULNERABILITIES = {
    "CVE-2008-2992": [r"/Collada", r"/3D"],
    "CVE-2009-0658": [r"\.getIcon", r"\.getAnnots"],
    "CVE-2009-0927": [r"\.spawnPageFromTemplate"],
    "CVE-2009-1492": [r"\.media\.newPlayer", r"\.createDataObject"],
    "CVE-2009-3459": [r"\.collectEmailInfo", r"\.getMailInfo"],
    "CVE-2010-1240": [r"\.colorConvertPage"],
    "CVE-2010-2883": [r"\.media\.newPlayer", r"\.getIcon"],
    "CVE-2011-2462": [r"\.spell\.customDictionaryOpen"],
    "CVE-2013-2729": [r"\.u3d", r"\.3d"],
    "CVE-2014-0496": [r"\.toolButton", r"\.checkThisBox"],
    "CVE-2015-3203": [r"\.newCollection", r"\.getAnnot"]
}

# Shellcode patterns in hex format
SHELLCODE_PATTERNS = [
    r"\\x90\\x90\\x90\\x90\\x90",  # NOP sled
    r"\\x31\\xc0\\x50\\x68",       # Common shellcode
    r"\\xeb\\x0c\\x5e\\x56",       # Jump shellcode pattern
    r"\\xfc\\xe8\\x82\\x00"        # Common Windows shellcode
]


def analyze_pdf(file_path: str) -> Dict[str, Any]:
    """
    Analyze a PDF file and extract static information
    """
    logger.info(f"Analyzing PDF file: {file_path}")
    
    # Initialize result structure
    result = {
        "version": None,
        "page_count": None,
        "has_javascript": False,
        "javascript_code": [],
        "has_forms": False,
        "has_embedded_files": False,
        "embedded_files": [],
        "has_auto_action": False,
        "auto_actions": [],
        "has_suspicious_objects": False,
        "suspicious_objects": [],
        "has_encryption": False,
        "has_obfuscation": False,
        "metadata": {},
        "acroform_fields": [],
        "xfa_forms": [],
        "urls": []
    }
    
    try:
        # Basic PDF analysis with PyPDF2
        with open(file_path, 'rb') as f:
            try:
                pdf = PdfReader(f)
                
                # Basic information
                result["page_count"] = len(pdf.pages)
                result["has_encryption"] = pdf.is_encrypted
                
                # Get PDF version
                if hasattr(pdf, 'pdf_header'):
                    version_match = re.search(r'%PDF-(\d+\.\d+)', pdf.pdf_header.decode('utf-8', 'ignore'))
                    if version_match:
                        result["version"] = version_match.group(1)
                
                # Extract metadata
                if hasattr(pdf, 'metadata') and pdf.metadata:
                    meta = pdf.metadata
                    metadata = {}
                    for key in meta:
                        try:
                            value = meta[key]
                            if isinstance(value, str):
                                metadata[key] = value
                            else:
                                metadata[key] = str(value)
                        except Exception:
                            continue
                    result["metadata"] = metadata
                
                # Check for forms
                if "/AcroForm" in pdf.get_page_dict():
                    result["has_forms"] = True
                
                # Extract direct URLs from text
                urls = []
                for page_num in range(len(pdf.pages)):
                    try:
                        page = pdf.pages[page_num]
                        text = page.extract_text()
                        # Find URLs in text
                        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
                        page_urls = re.findall(url_pattern, text)
                        urls.extend(page_urls)
                    except Exception as e:
                        logger.warning(f"Error extracting text from page {page_num}: {str(e)}")
                
                # Remove duplicate URLs
                result["urls"] = list(set(urls))
                
            except PdfReadError as e:
                logger.error(f"PyPDF2 error: {str(e)}")
                result["error"] = f"PDF parsing error: {str(e)}"
        
        # Advanced analysis with peepdf if available
        if PEEPDF_AVAILABLE:
            try:
                pdf_parser = PDFParser()
                ret, pdf = pdf_parser.parse(file_path, forceMode=True)
                
                if ret == 0:
                    stats = pdf.getStats()
                    
                    # Check for JavaScript
                    if stats.get('JS', 0) > 0:
                        result["has_javascript"] = True
                        js_code = []
                        for js in stats.get('JSCode', []):
                            if isinstance(js, list) and len(js) > 1:
                                js_code.append(js[1])
                        result["javascript_code"] = js_code
                    
                    # Check for automatic actions
                    if stats.get('Actions', 0) > 0:
                        result["has_auto_action"] = True
                        for action in stats.get('Actions', []):
                            if isinstance(action, list) and len(action) > 1:
                                result["auto_actions"].append({
                                    "type": action[0],
                                    "object_id": action[1]
                                })
                    
                    # Check for embedded files
                    if stats.get('EmbeddedFiles', 0) > 0:
                        result["has_embedded_files"] = True
                        for embedded_file in stats.get('EmbeddedFiles', []):
                            if isinstance(embedded_file, list) and len(embedded_file) > 1:
                                result["embedded_files"].append({
                                    "filename": embedded_file[0],
                                    "object_id": embedded_file[1]
                                })
                    
                    # Check for encryption
                    result["has_encryption"] = stats.get('Encrypted', False)
                    
                    # Check for obfuscation
                    result["has_obfuscation"] = stats.get('Obfuscated', False)
                    
                    # Extract suspicious elements
                    suspicious_objects = []
                    
                    # Check for suspicious names/patterns
                    for element_name, patterns in SUSPICIOUS_PDF_ELEMENTS.items():
                        for pattern in patterns:
                            matches = pdf.getReferences(pattern)
                            if matches:
                                for match in matches:
                                    suspicious_objects.append({
                                        "type": element_name,
                                        "pattern": pattern,
                                        "object_id": match
                                    })
                    
                    # Check for known vulnerabilities
                    for cve, patterns in PDF_VULNERABILITIES.items():
                        for pattern in patterns:
                            for obj_id in range(len(pdf.body)):
                                obj = pdf.getObject(obj_id, None)
                                if obj is not None and isinstance(obj, str):
                                    if re.search(pattern, obj, re.IGNORECASE):
                                        suspicious_objects.append({
                                            "type": "vulnerability",
                                            "cve": cve,
                                            "pattern": pattern,
                                            "object_id": obj_id
                                        })
                    
                    # Check for shellcode
                    for obj_id in range(len(pdf.body)):
                        obj = pdf.getObject(obj_id, None)
                        if obj is not None and isinstance(obj, str):
                            hex_content = str(obj).encode('string_escape')
                            for pattern in SHELLCODE_PATTERNS:
                                if re.search(pattern, hex_content, re.IGNORECASE):
                                    suspicious_objects.append({
                                        "type": "shellcode",
                                        "pattern": pattern,
                                        "object_id": obj_id
                                    })
                    
                    if suspicious_objects:
                        result["has_suspicious_objects"] = True
                        result["suspicious_objects"] = suspicious_objects
            
            except Exception as e:
                logger.error(f"peepdf analysis error: {str(e)}")
                # Continue with other analysis methods
        
        # Analyze raw file for additional patterns
        with open(file_path, 'rb') as f:
            content = f.read()
            content_str = content.decode('latin-1')  # Use latin-1 to avoid encoding errors
            
            # Check for additional JavaScript not found by the parsers
            js_patterns = [
                r'/JavaScript\s*<<.*?>>',
                r'/JS\s*<<.*?>>',
                r'/JavaScript\s*\(.*?\)',
                r'/JS\s*\(.*?\)',
                r'eval\s*\(',
                r'unescape\s*\('
            ]
            
            for pattern in js_patterns:
                if re.search(pattern, content_str, re.DOTALL | re.IGNORECASE):
                    result["has_javascript"] = True
                    break
            
            # Check for embedded files by pattern if not already found
            if not result["has_embedded_files"]:
                embedded_patterns = [
                    r'/EmbeddedFile\s*<<',
                    r'/EmbeddedFiles\s*<<',
                    r'/Filespec\s*<<'
                ]
                
                for pattern in embedded_patterns:
                    if re.search(pattern, content_str, re.DOTALL | re.IGNORECASE):
                        result["has_embedded_files"] = True
                        break
            
            # Check for auto-actions by pattern if not already found
            if not result["has_auto_action"]:
                action_patterns = [
                    r'/OpenAction\s*<<',
                    r'/AA\s*<<',
                    r'/Launch\s*<<'
                ]
                
                for pattern in action_patterns:
                    if re.search(pattern, content_str, re.DOTALL | re.IGNORECASE):
                        result["has_auto_action"] = True
                        break
    
    except Exception as e:
        logger.error(f"Error analyzing PDF file: {str(e)}")
        result["error"] = str(e)
    
    return result


def check_pdf_anomalies(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check for anomalies in the PDF analysis results
    """
    anomalies = []
    
    # Check for JavaScript
    if analysis_result.get("has_javascript", False):
        anomalies.append({
            "type": "javascript",
            "name": "JavaScript Found",
            "description": "PDF contains JavaScript code which can be used for malicious purposes",
            "severity": "medium"
        })
    
    # Check for auto actions
    if analysis_result.get("has_auto_action", False):
        anomalies.append({
            "type": "auto_action",
            "name": "Automatic Actions",
            "description": "PDF contains automatic actions that execute without user interaction",
            "severity": "high"
        })
    
    # Check for embedded files
    if analysis_result.get("has_embedded_files", False):
        anomalies.append({
            "type": "embedded_files",
            "name": "Embedded Files",
            "description": f"PDF contains {len(analysis_result.get('embedded_files', []))} embedded files which could contain malicious content",
            "severity": "medium"
        })
    
    # Check for encryption
    if analysis_result.get("has_encryption", False):
        anomalies.append({
            "type": "encryption",
            "name": "Encrypted PDF",
            "description": "PDF is encrypted which can be used to hide malicious content",
            "severity": "low"
        })
    
    # Check for obfuscation
    if analysis_result.get("has_obfuscation", False):
        anomalies.append({
            "type": "obfuscation",
            "name": "Obfuscated PDF",
            "description": "PDF contains obfuscated elements which can be used to hide malicious content",
            "severity": "high"
        })
    
    # Check for suspicious objects
    suspicious_objects = analysis_result.get("suspicious_objects", [])
    if suspicious_objects:
        # Group by type
        type_groups = {}
        for obj in suspicious_objects:
            obj_type = obj.get("type", "unknown")
            if obj_type not in type_groups:
                type_groups[obj_type] = []
            type_groups[obj_type].append(obj)
        
        # Create anomaly for each type
        for obj_type, objects in type_groups.items():
            if obj_type == "vulnerability":
                # Group by CVE
                cve_groups = {}
                for obj in objects:
                    cve = obj.get("cve", "unknown")
                    if cve not in cve_groups:
                        cve_groups[cve] = []
                    cve_groups[cve].append(obj)
                
                # Create anomaly for each CVE
                for cve, cve_objects in cve_groups.items():
                    anomalies.append({
                        "type": "vulnerability",
                        "name": f"Potential {cve} Vulnerability",
                        "description": f"PDF contains patterns associated with {cve} vulnerability",
                        "severity": "critical",
                        "details": cve_objects
                    })
            elif obj_type == "shellcode":
                anomalies.append({
                    "type": "shellcode",
                    "name": "Potential Shellcode",
                    "description": "PDF contains patterns that resemble shellcode execution",
                    "severity": "critical",
                    "details": objects
                })
            else:
                anomalies.append({
                    "type": obj_type,
                    "name": f"Suspicious {obj_type.capitalize()} Elements",
                    "description": f"PDF contains suspicious {obj_type} elements that could be used for malicious purposes",
                    "severity": "medium",
                    "details": objects
                })
    
    # Check for suspicious URLs
    urls = analysis_result.get("urls", [])
    suspicious_urls = []
    for url in urls:
        if any(pattern in url.lower() for pattern in ["pastebin", "bit.ly", "tinyurl", "goo.gl", "t.co"]):
            suspicious_urls.append(url)
    
    if suspicious_urls:
        anomalies.append({
            "type": "suspicious_urls",
            "name": "Suspicious URLs",
            "description": f"PDF contains {len(suspicious_urls)} suspicious URLs that may lead to malicious content",
            "severity": "medium",
            "details": suspicious_urls
        })
    
    return anomalies