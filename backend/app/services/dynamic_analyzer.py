# backend/app/services/dynamic_analyzer.py

import logging
import os
import subprocess
import tempfile
import json
import time
from typing import Dict, Any, List, Optional
import threading
import queue
import psutil
import socket
import requests
from contextlib import contextmanager

from app.core.config import settings
from app.models.schemas import FileType

logger = logging.getLogger(__name__)

# Set up a safe, isolated environment for dynamic analysis
SANDBOX_TIMEOUT = 60  # Maximum runtime in seconds
NETWORK_MONITORING_PORT = 8765  # Port to use for network monitoring proxy

class NetworkMonitor:
    """Monitors network activity during dynamic analysis"""
    
    def __init__(self):
        self.connections = []
        self.dns_requests = []
        self.http_requests = []
        self.is_monitoring = False
        self._thread = None
        self._stop_event = threading.Event()
    
    def start(self):
        """Start network monitoring"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_network)
        self._thread.daemon = True
        self._thread.start()
        
    def stop(self):
        """Stop network monitoring"""
        if not self.is_monitoring:
            return
            
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.is_monitoring = False
    
    def _monitor_network(self):
        """Monitor network connections"""
        initial_connections = psutil.net_connections()
        initial_conns_set = {(c.laddr, c.raddr, c.status) for c in initial_connections if c.raddr}
        
        while not self._stop_event.is_set():
            # Monitor new network connections
            current_connections = psutil.net_connections()
            current_conns_set = {(c.laddr, c.raddr, c.status) for c in current_connections if c.raddr}
            
            # Find new connections
            new_conns = current_conns_set - initial_conns_set
            
            for conn in new_conns:
                local_addr, remote_addr, status = conn
                self.connections.append({
                    "local_address": f"{local_addr[0]}:{local_addr[1]}",
                    "remote_address": f"{remote_addr[0]}:{remote_addr[1]}",
                    "status": status,
                    "timestamp": time.time()
                })
                
                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(remote_addr[0])[0]
                    self.dns_requests.append({
                        "ip": remote_addr[0],
                        "hostname": hostname,
                        "timestamp": time.time()
                    })
                except:
                    pass
            
            initial_conns_set = current_conns_set
            time.sleep(0.5)
    
    def get_results(self) -> Dict[str, Any]:
        """Get network monitoring results"""
        return {
            "connections": self.connections,
            "dns_requests": self.dns_requests,
            "http_requests": self.http_requests
        }


class ProcessMonitor:
    """Monitors process activity during dynamic analysis"""
    
    def __init__(self, main_pid: int):
        self.main_pid = main_pid
        self.child_processes = []
        self.file_operations = []
        self.registry_operations = []
        self.api_calls = []
        self.is_monitoring = False
        self._thread = None
        self._stop_event = threading.Event()
    
    def start(self):
        """Start process monitoring"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_process)
        self._thread.daemon = True
        self._thread.start()
    
    def stop(self):
        """Stop process monitoring"""
        if not self.is_monitoring:
            return
            
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.is_monitoring = False
    
    def _monitor_process(self):
        """Monitor process activity"""
        try:
            main_process = psutil.Process(self.main_pid)
            initial_children = set()
            
            # Record initial state
            try:
                for child in main_process.children(recursive=True):
                    initial_children.add(child.pid)
            except:
                pass
            
            while not self._stop_event.is_set():
                try:
                    # Check if process is still running
                    if not psutil.pid_exists(self.main_pid):
                        break
                        
                    # Monitor for new child processes
                    current_children = set()
                    try:
                        for child in main_process.children(recursive=True):
                            current_children.add(child.pid)
                            
                            # If this is a new child process
                            if child.pid not in initial_children:
                                self.child_processes.append({
                                    "pid": child.pid,
                                    "name": child.name(),
                                    "cmdline": child.cmdline(),
                                    "creation_time": child.create_time(),
                                    "timestamp": time.time()
                                })
                    except:
                        pass
                    
                    initial_children = current_children
                    
                    # Monitor file operations (simplified)
                    # In a real system, this would use ptrace, ETW, or similar
                    
                    # Monitor API calls (simplified)
                    # In a real system, this would use API hooking
                    
                    time.sleep(1)
                except:
                    break
        except:
            logger.error("Error monitoring process", exc_info=True)
    
    def get_results(self) -> Dict[str, Any]:
        """Get process monitoring results"""
        return {
            "child_processes": self.child_processes,
            "file_operations": self.file_operations,
            "registry_operations": self.registry_operations,
            "api_calls": self.api_calls
        }


@contextmanager
def run_in_sandbox(file_path: str) -> Dict[str, Any]:
    """
    Run an executable in a sandboxed environment and monitor its behavior
    Returns information about the execution behavior
    """
    # Create a temporary directory for sandbox
    with tempfile.TemporaryDirectory() as sandbox_dir:
        # Prepare monitoring components
        network_monitor = NetworkMonitor()
        
        try:
            # Start network monitoring
            network_monitor.start()
            
            # Run the executable in a subprocess with timeout
            process = subprocess.Popen(
                [file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=sandbox_dir,
                shell=False
            )
            
            # Start process monitoring
            process_monitor = ProcessMonitor(process.pid)
            process_monitor.start()
            
            try:
                # Wait for process to complete or timeout
                stdout, stderr = process.communicate(timeout=SANDBOX_TIMEOUT)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                # Process took too long, terminate it
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -1
            
            # Get results from monitors
            network_results = network_monitor.get_results()
            process_results = process_monitor.get_results()
            
            # Combine results
            results = {
                "exit_code": exit_code,
                "execution_time": SANDBOX_TIMEOUT if exit_code == -1 else None,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "network": network_results,
                "process": process_results
            }
            
            yield results
            
        finally:
            # Always stop monitoring
            network_monitor.stop()
            if 'process_monitor' in locals():
                process_monitor.stop()
            
            # Ensure any remaining processes are terminated
            if 'process' in locals() and process.poll() is None:
                try:
                    process.kill()
                except:
                    pass


def analyze_exe_dynamically(file_path: str) -> Dict[str, Any]:
    """
    Perform dynamic analysis on an executable file
    """
    logger.info(f"Starting dynamic analysis for: {file_path}")
    
    # Skip dynamic analysis if it's disabled in settings
    if not settings.ENABLE_DYNAMIC_ANALYSIS:
        logger.info("Dynamic analysis is disabled in settings")
        return {
            "dynamic_analysis_enabled": False,
            "message": "Dynamic analysis is disabled in system settings"
        }
    
    try:
        # Create a copy of the file for analysis to avoid modifying the original
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_file:
            temp_path = temp_file.name
            with open(file_path, 'rb') as src_file:
                temp_file.write(src_file.read())
        
        # Run the file in a sandbox and collect results
        with run_in_sandbox(temp_path) as sandbox_results:
            # Analyze the sandbox results
            dynamic_results = {
                "dynamic_analysis_enabled": True,
                "execution": {
                    "exit_code": sandbox_results["exit_code"],
                    "execution_time": sandbox_results["execution_time"],
                    "stdout_size": len(sandbox_results["stdout"]),
                    "stderr_size": len(sandbox_results["stderr"]),
                    "crashed": sandbox_results["exit_code"] != 0 and sandbox_results["exit_code"] != -1,
                    "timeout": sandbox_results["exit_code"] == -1,
                },
                "network_activity": {
                    "connection_count": len(sandbox_results["network"]["connections"]),
                    "dns_request_count": len(sandbox_results["network"]["dns_requests"]),
                    "http_request_count": len(sandbox_results["network"]["http_requests"]),
                    "connections": sandbox_results["network"]["connections"],
                    "dns_requests": sandbox_results["network"]["dns_requests"],
                    "http_requests": sandbox_results["network"]["http_requests"],
                    "has_network_activity": len(sandbox_results["network"]["connections"]) > 0,
                },
                "process_activity": {
                    "created_processes": len(sandbox_results["process"]["child_processes"]),
                    "file_operations": len(sandbox_results["process"]["file_operations"]),
                    "registry_operations": len(sandbox_results["process"]["registry_operations"]),
                    "api_calls": len(sandbox_results["process"]["api_calls"]),
                    "child_processes": sandbox_results["process"]["child_processes"],
                    "has_child_processes": len(sandbox_results["process"]["child_processes"]) > 0,
                },
                "behavior_summary": generate_behavior_summary(sandbox_results)
            }
            
            # Detect suspicious behavior patterns
            dynamic_results["suspicious_behaviors"] = detect_suspicious_behaviors(sandbox_results)
            
            # Add maliciousness score based on dynamic analysis
            dynamic_results["maliciousness_score"] = calculate_maliciousness_score(sandbox_results)
            
            return dynamic_results
            
    except Exception as e:
        logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
        return {
            "dynamic_analysis_enabled": True,
            "error": str(e),
            "message": "Dynamic analysis failed"
        }
    finally:
        # Clean up temporary file
        if 'temp_path' in locals():
            try:
                os.remove(temp_path)
            except:
                pass


def generate_behavior_summary(sandbox_results: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of program behavior
    """
    summary_parts = []
    
    # Execution summary
    if sandbox_results["exit_code"] == 0:
        summary_parts.append("The program executed successfully.")
    elif sandbox_results["exit_code"] == -1:
        summary_parts.append("The program execution timed out.")
    else:
        summary_parts.append(f"The program crashed or exited with code {sandbox_results['exit_code']}.")
    
    # Network activity summary
    connections = sandbox_results["network"]["connections"]
    dns_requests = sandbox_results["network"]["dns_requests"]
    http_requests = sandbox_results["network"]["http_requests"]
    
    if connections:
        summary_parts.append(f"Made {len(connections)} network connection(s).")
        
        # List some domains/IPs
        remote_addrs = [conn["remote_address"].split(":")[0] for conn in connections[:3]]
        if remote_addrs:
            summary_parts.append(f"Connected to: {', '.join(remote_addrs)}{' and others' if len(connections) > 3 else ''}.")
    
    if dns_requests:
        hostnames = [req["hostname"] for req in dns_requests[:3]]
        if hostnames:
            summary_parts.append(f"Resolved hostnames: {', '.join(hostnames)}{' and others' if len(dns_requests) > 3 else ''}.")
    
    # Process activity summary
    child_processes = sandbox_results["process"]["child_processes"]
    if child_processes:
        summary_parts.append(f"Created {len(child_processes)} child process(es).")
        
        # List some process names
        process_names = [proc["name"] for proc in child_processes[:3]]
        if process_names:
            summary_parts.append(f"Processes: {', '.join(process_names)}{' and others' if len(child_processes) > 3 else ''}.")
    
    # File operations summary
    file_ops = sandbox_results["process"]["file_operations"]
    if file_ops:
        summary_parts.append(f"Performed {len(file_ops)} file operation(s).")
    
    # Registry operations summary
    reg_ops = sandbox_results["process"]["registry_operations"]
    if reg_ops:
        summary_parts.append(f"Performed {len(reg_ops)} registry operation(s).")
    
    # Return the complete summary
    return " ".join(summary_parts)


def detect_suspicious_behaviors(sandbox_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect suspicious behaviors from sandbox results
    """
    suspicious_behaviors = []
    
    # Check for network connections to suspicious IPs/domains
    connections = sandbox_results["network"]["connections"]
    dns_requests = sandbox_results["network"]["dns_requests"]
    
    # Suspicious domains (simplified - in a real system, this would check against threat intelligence)
    suspicious_domains = ["malware", "evil", "attack", "exploit", "botnet", "command", "control"]
    
    for dns_req in dns_requests:
        hostname = dns_req["hostname"].lower()
        for suspicious in suspicious_domains:
            if suspicious in hostname:
                suspicious_behaviors.append({
                    "type": "suspicious_domain",
                    "severity": "high",
                    "description": f"DNS request to suspicious domain: {hostname}",
                    "details": dns_req
                })
                break
    
    # Check for process creation patterns
    child_processes = sandbox_results["process"]["child_processes"]
    suspicious_process_names = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
    
    for proc in child_processes:
        name = proc["name"].lower()
        if name in suspicious_process_names:
            suspicious_behaviors.append({
                "type": "suspicious_process",
                "severity": "medium", 
                "description": f"Created potentially suspicious process: {name}",
                "details": proc
            })
    
    # Check for high volume of connections
    if len(connections) > 10:
        suspicious_behaviors.append({
            "type": "high_connection_volume",
            "severity": "medium",
            "description": f"High number of network connections: {len(connections)}",
            "details": {"connection_count": len(connections)}
        })
    
    # Check for specific HTTP requests (would be more detailed in a real implementation)
    http_requests = sandbox_results["network"]["http_requests"]
    for req in http_requests:
        if "url" in req and any(s in req["url"].lower() for s in ["/admin", "/login", "/upload", "/exec"]):
            suspicious_behaviors.append({
                "type": "suspicious_http_request",
                "severity": "medium",
                "description": f"Suspicious HTTP request: {req['url']}",
                "details": req
            })
    
    return suspicious_behaviors


def calculate_maliciousness_score(sandbox_results: Dict[str, Any]) -> float:
    """
    Calculate a maliciousness score based on dynamic behavior
    0.0 = benign, 1.0 = definitely malicious
    """
    score = 0.0
    
    # Network indicators
    connections = sandbox_results["network"]["connections"]
    dns_requests = sandbox_results["network"]["dns_requests"]
    
    if connections:
        # More connections = higher score, max 0.3
        score += min(0.3, len(connections) * 0.03)
    
    # Process creation indicators
    child_processes = sandbox_results["process"]["child_processes"]
    if child_processes:
        # More process creation = higher score, max 0.3
        score += min(0.3, len(child_processes) * 0.05)
    
    # Check for suspicious process names
    suspicious_process_names = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
    for proc in child_processes:
        name = proc["name"].lower()
        if name in suspicious_process_names:
            score += 0.1
    
    # Execution indicators
    if sandbox_results["exit_code"] == -1:  # Timeout
        score += 0.1
    
    # Cap the score at 1.0
    return min(1.0, score)