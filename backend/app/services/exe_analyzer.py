import logging
import os
import time
import re
import tempfile
import subprocess
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import pefile
import string
import yara
import magic

from app.core.config import settings

logger = logging.getLogger(__name__)

# Common malicious API calls for Windows executables
SUSPICIOUS_API_CALLS = {
    "network": [
        "InternetOpen", "InternetOpenUrl", "InternetReadFile", "InternetWriteFile",
        "URLDownloadToFile", "HttpOpenRequest", "HttpSendRequest", "WSAStartup",
        "socket", "connect", "recv", "send", "bind", "listen", "accept"
    ],
    "process": [
        "CreateProcess", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
        "CreateRemoteThread", "OpenProcess", "TerminateProcess", "ExitProcess",
        "CreateThread", "NtCreateThreadEx", "QueueUserAPC"
    ],
    "registry": [
        "RegOpenKey", "RegCreateKey", "RegSetValue", "RegQueryValue",
        "RegDeleteKey", "RegEnumKey", "RegSaveKey"
    ],
    "file": [
        "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile",
        "MoveFile", "SetFileAttributes", "GetTempPath", "GetTempFileName"
    ],
    "system": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
        "GetTickCount", "GetSystemTime", "GetVersionEx", "GetComputerName",
        "GetUserName", "GetSystemDirectory", "GetWindowsDirectory"
    ],
    "crypto": [
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
        "CryptEncrypt", "CryptDecrypt", "CryptGenRandom"
    ],
    "keylogging": [
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "RegisterHotKey", "GetMessage", "PeekMessage"
    ],
    "injection": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtMapViewOfSection", "ZwMapViewOfSection", "SetThreadContext"
    ]
}

# Common packer signatures
PACKER_SIGNATURES = {
    "UPX": [r"UPX\d\.\d\d", r"UPX\!"],
    "ASPack": [r"ASPack"],
    "PECompact": [r"PECompact2"],
    "Themida": [r"Themida"],
    "VMProtect": [r"VMProtect"],
    "MPress": [r"MPRESS"],
    "Obsidium": [r"Obsidium"],
    "Enigma": [r"Enigma"],
    "PESpin": [r"PESpin"],
    "ExeStealth": [r"ExeStealth"],
}

# PE section characteristics flags
SECTION_CHARACTERISTICS = {
    0x20000000: "CNT_CODE",               # Section contains executable code
    0x40000000: "CNT_INITIALIZED_DATA",   # Section contains initialized data
    0x80000000: "CNT_UNINITIALIZED_DATA", # Section contains uninitialized data
    0x00000020: "MEM_EXECUTE",            # Section is executable
    0x00000040: "MEM_READ",               # Section is readable
    0x00000080: "MEM_WRITE",              # Section is writable
    0x02000000: "MEM_DISCARDABLE",        # Section can be discarded
    0x04000000: "MEM_NOT_CACHED",         # Section cannot be cached
    0x08000000: "MEM_NOT_PAGED",          # Section is not pageable
    0x10000000: "MEM_SHARED"              # Section can be shared in memory
}


def analyze_exe(file_path: str) -> Dict[str, Any]:
    """
    Analyze an EXE file and extract static information
    """
    logger.info(f"Analyzing EXE file: {file_path}")
    
    # Initialize result structure
    result = {
        "architecture": None,
        "is_packed": False,
        "packer_type": None,
        "imports": [],
        "exports": [],
        "sections": [],
        "libraries": [],
        "entry_point": None,
        "compile_time": None,
        "digital_signature": None,
        "strings_of_interest": [],
        "resources": [],
        "pe_characteristics": {},
        "is_dll": False,
        "is_driver": False,
        "is_exe": True,
        "subsystem": None
    }
    
    try:
        # Use pefile to parse the PE file
        pe = pefile.PE(file_path)
        
        # Get basic information
        result["architecture"] = "32-bit" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"] else "64-bit"
        result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"])
        result["is_driver"] = pe.is_driver() if hasattr(pe, "is_driver") else False
        result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        
        # Get subsystem
        subsystem_map = {
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_NATIVE"]: "Native",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_WINDOWS_GUI"]: "Windows GUI",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_WINDOWS_CUI"]: "Windows Console",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_OS2_CUI"]: "OS/2 Console",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_POSIX_CUI"]: "POSIX Console",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"]: "Windows CE GUI",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_EFI_APPLICATION"]: "EFI Application",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"]: "EFI Boot Service Driver",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"]: "EFI Runtime Driver",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_EFI_ROM"]: "EFI ROM",
            pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_XBOX"]: "XBOX"
        }
        result["subsystem"] = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")
        
        # Get compile time
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            result["compile_time"] = datetime.fromtimestamp(timestamp).isoformat()
        except Exception:
            result["compile_time"] = hex(timestamp)
        
        # Get PE file characteristics
        characteristics = {}
        for flag, name in pefile.IMAGE_CHARACTERISTICS.items():
            if pe.FILE_HEADER.Characteristics & flag:
                characteristics[name] = True
        result["pe_characteristics"] = characteristics
        
        # Analyze sections
        sections = []
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            section_info = {
                "name": section_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
                "md5": section.get_hash_md5(),
                "characteristics": []
            }
            
            # Add section characteristics
            for flag, name in SECTION_CHARACTERISTICS.items():
                if section.Characteristics & flag:
                    section_info["characteristics"].append(name)
            
            sections.append(section_info)
        
        result["sections"] = sections
        
        # Check for packing
        is_packed, packer = check_if_packed(pe, sections)
        result["is_packed"] = is_packed
        result["packer_type"] = packer
        
        # Get imports
        imports = []
        libraries = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                library = entry.dll.decode('utf-8', 'ignore')
                libraries.append(library)
                
                for imp in entry.imports:
                    if imp.name:
                        import_name = imp.name.decode('utf-8', 'ignore')
                        imports.append(f"{library}:{import_name}")
                    else:
                        imports.append(f"{library}:ordinal_{imp.ordinal}")
        
        result["imports"] = imports
        result["libraries"] = libraries
        
        # Get exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    export_name = exp.name.decode('utf-8', 'ignore')
                    exports.append(export_name)
                else:
                    exports.append(f"ordinal_{exp.ordinal}")
        
        result["exports"] = exports
        
        # Get resources
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    resource_type_str = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))
                    
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            resource_data = pe.get_data(
                                resource_lang.data.struct.OffsetToData,
                                resource_lang.data.struct.Size
                            )
                            
                            resources.append({
                                "type": resource_type_str,
                                "id": resource_id.id,
                                "language": resource_lang.id,
                                "size": resource_lang.data.struct.Size,
                                "md5": hashlib.md5(resource_data).hexdigest()
                            })
                except Exception as e:
                    logger.warning(f"Error extracting resource: {str(e)}")
        
        result["resources"] = resources
        
        # Check for digital signature
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            result["digital_signature"] = {
                "address": pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress,
                "size": pe.DIRECTORY_ENTRY_SECURITY.Size,
                "present": True
            }
        
        # Extract strings of interest
        result["strings_of_interest"] = extract_interesting_strings(file_path)
        
        # Clean up
        pe.close()
        
    except Exception as e:
        logger.error(f"Error analyzing EXE file: {str(e)}")
        result["error"] = str(e)
    
    return result


def check_if_packed(pe, sections) -> tuple[bool, Optional[str]]:
    """
    Check if a PE file is packed based on various heuristics
    """
    # Check high entropy in code section
    high_entropy_sections = [s for s in sections if s["entropy"] > 7.0]
    
    # Check for few imports
    few_imports = len(pe.DIRECTORY_ENTRY_IMPORT) < 3 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else True
    
    # Check section names for packer signatures
    section_names = [s["name"] for s in sections]
    
    # Check for known packer signatures in section names
    for packer, signatures in PACKER_SIGNATURES.items():
        for section_name in section_names:
            for signature in signatures:
                if re.search(signature, section_name, re.IGNORECASE):
                    return True, packer
    
    # Check for UPX in imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if b"UPX" in entry.dll:
                return True, "UPX"
    
    # Heuristic-based detection
    if len(high_entropy_sections) > 0 and few_imports:
        return True, "Unknown Packer"
    
    # Check for small number of sections with unusual names
    if len(sections) < 3 and not all(s["name"] in [".text", ".data", ".rdata", ".rsrc", ".reloc"] for s in sections):
        return True, "Possible Custom Packer"
    
    return False, None


def extract_interesting_strings(file_path: str) -> List[str]:
    """
    Extract strings of interest from the binary
    """
    interesting_strings = []
    
    # Define patterns for interesting strings
    patterns = {
        "url": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "ip": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "registry": r'HKEY_[A-Z_]+\\[A-Za-z0-9_\\]+',
        "file_path": r'[A-Za-z]:\\[A-Za-z0-9_\\]+\.[a-zA-Z0-9]{2,4}',
        "api_calls": r'\b(?:' + '|'.join(sum([calls for calls in SUSPICIOUS_API_CALLS.values()], [])) + r')\b'
    }
    
    try:
        # Read the binary file
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Extract ASCII strings
        ascii_strings = re.findall(b'[\x20-\x7E]{4,}', content)
        ascii_strings = [s.decode('ascii') for s in ascii_strings]
        
        # Extract Unicode strings (simple approach)
        unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', content)
        unicode_strings = [s.decode('utf-16-le', errors='ignore') for s in unicode_strings]
        
        # Combine all strings
        all_strings = ascii_strings + unicode_strings
        
        # Filter for interesting strings
        for pattern_name, pattern in patterns.items():
            for string in all_strings:
                matches = re.findall(pattern, string)
                for match in matches:
                    interesting_strings.append({
                        "type": pattern_name,
                        "value": match
                    })
        
        # Deduplicate
        unique_strings = []
        seen = set()
        for item in interesting_strings:
            key = f"{item['type']}:{item['value']}"
            if key not in seen:
                seen.add(key)
                unique_strings.append(item)
        
        return unique_strings
    
    except Exception as e:
        logger.error(f"Error extracting strings: {str(e)}")
        return []


def check_exe_anomalies(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check for anomalies in the EXE analysis results
    """
    anomalies = []
    
    # Check for packing
    if analysis_result.get("is_packed", False):
        anomalies.append({
            "type": "packing",
            "name": "Packed Executable",
            "description": f"File appears to be packed with {analysis_result.get('packer_type', 'unknown packer')}",
            "severity": "medium"
        })
    
    # Check for suspicious imports
    suspicious_imports = []
    for import_name in analysis_result.get("imports", []):
        for category, apis in SUSPICIOUS_API_CALLS.items():
            for api in apis:
                if api in import_name:
                    suspicious_imports.append({
                        "name": import_name,
                        "category": category
                    })
    
    if suspicious_imports:
        categories = set(item["category"] for item in suspicious_imports)
        for category in categories:
            imports_in_category = [item["name"] for item in suspicious_imports if item["category"] == category]
            anomalies.append({
                "type": "suspicious_imports",
                "name": f"Suspicious {category.capitalize()} API Calls",
                "description": f"File imports potentially malicious {category} APIs: {', '.join(imports_in_category[:5])}",
                "severity": "medium",
                "details": imports_in_category
            })
    
    # Check for high entropy sections
    high_entropy_sections = [
        section["name"] for section in analysis_result.get("sections", [])
        if section.get("entropy", 0) > 7.0
    ]
    
    if high_entropy_sections:
        anomalies.append({
            "type": "high_entropy",
            "name": "High Entropy Sections",
            "description": f"File contains high-entropy sections which may indicate encryption or packing: {', '.join(high_entropy_sections)}",
            "severity": "medium",
            "details": high_entropy_sections
        })
    
    # Check for executable sections that are both writable and executable
    writable_executable_sections = [
        section["name"] for section in analysis_result.get("sections", [])
        if "MEM_WRITE" in section.get("characteristics", []) and "MEM_EXECUTE" in section.get("characteristics", [])
    ]
    
    if writable_executable_sections:
        anomalies.append({
            "type": "writable_executable",
            "name": "Writable and Executable Sections",
            "description": f"File contains sections that are both writable and executable which is often used for shellcode: {', '.join(writable_executable_sections)}",
            "severity": "high",
            "details": writable_executable_sections
        })
    
    # Check for digital signature
    if not analysis_result.get("digital_signature", {}).get("present", False):
        anomalies.append({
            "type": "no_signature",
            "name": "Unsigned Executable",
            "description": "File is not digitally signed",
            "severity": "low"
        })
    
    # Check for suspicious strings
    suspicious_urls = [
        s["value"] for s in analysis_result.get("strings_of_interest", [])
        if s["type"] == "url" and ("pastebin" in s["value"] or "bit.ly" in s["value"] or "tinyurl" in s["value"])
    ]
    
    if suspicious_urls:
        anomalies.append({
            "type": "suspicious_urls",
            "name": "Suspicious URLs",
            "description": f"File contains suspicious shortener or pastebin URLs: {', '.join(suspicious_urls[:5])}",
            "severity": "high",
            "details": suspicious_urls
        })
    
    # Check for suspicious registry keys
    suspicious_registry = [
        s["value"] for s in analysis_result.get("strings_of_interest", [])
        if s["type"] == "registry" and ("Run" in s["value"] or "StartUp" in s["value"])
    ]
    
    if suspicious_registry:
        anomalies.append({
            "type": "autorun_registry",
            "name": "Autorun Registry Keys",
            "description": f"File contains references to registry keys used for persistence: {', '.join(suspicious_registry[:5])}",
            "severity": "high",
            "details": suspicious_registry
        })
    
    return anomalies