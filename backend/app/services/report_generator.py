import logging
import os
import json
import tempfile
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import jinja2
import weasyprint
import base64
import matplotlib
matplotlib.use('Agg')  # Use Agg backend
import matplotlib.pyplot as plt
import numpy as np
import io

from app.core.config import settings
from app.models.schemas import FileType, SeverityLevel, MalwareCategory

logger = logging.getLogger(__name__)

# Setup Jinja2 template environment
template_loader = jinja2.FileSystemLoader(searchpath="./templates")
template_env = jinja2.Environment(loader=template_loader)


def generate_report(task_id: str, format: str = "pdf", analysis_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a report for an analysis task
    Returns the path to the generated report
    """
    logger.info(f"Generating {format} report for task {task_id}")
    
    # If analysis_data is not provided, load it from the results storage
    # In a real application, this would load from a database
    if analysis_data is None:
        from app.services.analyzer import analysis_results
        if task_id not in analysis_results:
            raise ValueError(f"No analysis results found for task {task_id}")
        analysis_data = analysis_results[task_id].get("result", {})
    
    # Ensure reports directory exists
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    
    if format == "pdf":
        return generate_pdf_report(task_id, analysis_data)
    elif format == "json":
        return generate_json_report(task_id, analysis_data)
    elif format == "html":
        return generate_html_report(task_id, analysis_data)
    else:
        raise ValueError(f"Unsupported report format: {format}")


def generate_pdf_report(task_id: str, analysis_data: Dict[str, Any]) -> str:
    """
    Generate a PDF report for the analysis results
    """
    # First generate the HTML report
    html_path = generate_html_report(task_id, analysis_data)
    
    # Define the PDF output path
    pdf_path = os.path.join(settings.REPORTS_DIR, f"{task_id}.pdf")
    
    try:
        # Convert HTML to PDF using WeasyPrint
        with open(html_path, 'r') as html_file:
            html_content = html_file.read()
        
        # Create PDF
        pdf = weasyprint.HTML(string=html_content).write_pdf()
        
        # Save PDF to file
        with open(pdf_path, 'wb') as pdf_file:
            pdf_file.write(pdf)
        
        logger.info(f"PDF report generated: {pdf_path}")
        return pdf_path
    
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        
        # Return a simplified PDF with error message if HTML-to-PDF conversion fails
        simplified_html = f"""
        <html>
        <body>
            <h1>Static Malware Analysis Report</h1>
            <h2>Error Generating Full Report</h2>
            <p>An error occurred during report generation: {str(e)}</p>
            <p>Task ID: {task_id}</p>
            <p>Analysis Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>Please check the JSON report for complete analysis results.</p>
        </body>
        </html>
        """
        
        # Try again with simplified HTML
        try:
            pdf = weasyprint.HTML(string=simplified_html).write_pdf()
            with open(pdf_path, 'wb') as pdf_file:
                pdf_file.write(pdf)
            return pdf_path
        except Exception as simplified_error:
            logger.error(f"Error generating simplified PDF report: {str(simplified_error)}")
            # Create an empty PDF file as placeholder
            with open(pdf_path, 'wb') as pdf_file:
                pdf_file.write(b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj xref 0 4 0000000000 65535 f 0000000010 00000 n 0000000053 00000 n 0000000102 00000 n trailer<</Size 4/Root 1 0 R>>startxref 178 %%EOF')
            return pdf_path


def generate_html_report(task_id: str, analysis_data: Dict[str, Any]) -> str:
    """
    Generate an HTML report for the analysis results
    """
    # Define the HTML output path
    html_path = os.path.join(settings.REPORTS_DIR, f"{task_id}.html")
    
    try:
        # Get template
        try:
            template = template_env.get_template("report_template.html")
        except jinja2.exceptions.TemplateNotFound:
            # Create a basic template if the template file doesn't exist
            template_str = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Static Malware Analysis Report</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
                    h1, h2, h3 { color: #2c3e50; }
                    .header { text-align: center; margin-bottom: 30px; }
                    .section { margin-bottom: 30px; }
                    .summary { background-color: #f8f9fa; padding: 15px; border-left: 5px solid #5bc0de; margin-bottom: 20px; }
                    .file-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
                    .indicators { margin-top: 20px; }
                    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #f2f2f2; }
                    tr:hover { background-color: #f5f5f5; }
                    .severity-high { color: #d9534f; }
                    .severity-medium { color: #f0ad4e; }
                    .severity-low { color: #5bc0de; }
                    .severity-clean { color: #5cb85c; }
                    .severity-unknown { color: #777; }
                    .visualization { margin: 20px 0; text-align: center; }
                    .footer { margin-top: 50px; text-align: center; font-size: 0.8em; color: #777; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Static Malware Analysis Report</h1>
                    <p>Generated on {{ report_time }}</p>
                </div>
                
                <div class="section summary">
                    <h2>Analysis Summary</h2>
                    <p><strong>Verdict:</strong> 
                        <span class="severity-{{ analysis.severity }}">
                            {{ analysis.severity|upper }} Risk - {{ analysis.malware_category }}
                            (Score: {{ "%.2f"|format(analysis.malware_score) }})
                        </span>
                    </p>
                    <p><strong>Confidence:</strong> {{ "%.2f"|format(analysis.confidence) }}</p>
                    <p><strong>Analysis Time:</strong> {{ analysis.analysis_time }}</p>
                    <p><strong>Summary:</strong> {{ analysis.static_analysis_summary }}</p>
                    {% if analysis.malware_family %}
                    <p><strong>Malware Family:</strong> {{ analysis.malware_family }}</p>
                    {% endif %}
                    <p><strong>Recommendation:</strong> {{ analysis.recommendation }}</p>
                </div>
                
                <div class="section file-info">
                    <h2>File Information</h2>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>File Name</td>
                            <td>{{ analysis.file_info.original_filename }}</td>
                        </tr>
                        <tr>
                            <td>File Type</td>
                            <td>{{ analysis.file_info.file_type }}</td>
                        </tr>
                        <tr>
                            <td>File Size</td>
                            <td>{{ analysis.file_info.file_size|filesizeformat }}</td>
                        </tr>
                        <tr>
                            <td>MD5</td>
                            <td>{{ analysis.file_info.md5 }}</td>
                        </tr>
                        <tr>
                            <td>SHA1</td>
                            <td>{{ analysis.file_info.sha1 }}</td>
                        </tr>
                        <tr>
                            <td>SHA256</td>
                            <td>{{ analysis.file_info.sha256 }}</td>
                        </tr>
                        <tr>
                            <td>MIME Type</td>
                            <td>{{ analysis.file_info.mime_type }}</td>
                        </tr>
                        <tr>
                            <td>Upload Time</td>
                            <td>{{ analysis.file_info.upload_time }}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="section indicators">
                    <h2>Detected Indicators ({{ analysis.indicators|length }})</h2>
                    {% if analysis.indicators %}
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Severity</th>
                        </tr>
                        {% for indicator in analysis.indicators %}
                        <tr>
                            <td>{{ indicator.type }}</td>
                            <td>{{ indicator.name }}</td>
                            <td>{{ indicator.description }}</td>
                            <td class="severity-{{ indicator.severity }}">{{ indicator.severity|upper }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <p>No indicators detected.</p>
                    {% endif %}
                </div>
                
                <div class="visualization">
                    <h2>Analysis Visualization</h2>
                    {% if malware_score_chart %}
                    <img src="data:image/png;base64,{{ malware_score_chart }}" alt="Malware Score Chart">
                    {% endif %}
                </div>
                
                {% if analysis.exe_details %}
                <div class="section">
                    <h2>Executable Details</h2>
                    
                    <h3>General Information</h3>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Architecture</td>
                            <td>{{ analysis.exe_details.architecture }}</td>
                        </tr>
                        <tr>
                            <td>Subsystem</td>
                            <td>{{ analysis.exe_details.subsystem }}</td>
                        </tr>
                        <tr>
                            <td>Compile Time</td>
                            <td>{{ analysis.exe_details.compile_time }}</td>
                        </tr>
                        <tr>
                            <td>Is Packed</td>
                            <td>{{ analysis.exe_details.is_packed }}</td>
                        </tr>
                        {% if analysis.exe_details.is_packed %}
                        <tr>
                            <td>Packer Type</td>
                            <td>{{ analysis.exe_details.packer_type }}</td>
                        </tr>
                        {% endif %}
                        <tr>
                            <td>Is DLL</td>
                            <td>{{ analysis.exe_details.is_dll }}</td>
                        </tr>
                        <tr>
                            <td>Is Driver</td>
                            <td>{{ analysis.exe_details.is_driver }}</td>
                        </tr>
                        <tr>
                            <td>Entry Point</td>
                            <td>{{ analysis.exe_details.entry_point }}</td>
                        </tr>
                    </table>
                    
                    <h3>Sections ({{ analysis.exe_details.sections|length }})</h3>
                    {% if analysis.exe_details.sections %}
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Entropy</th>
                            <th>Characteristics</th>
                        </tr>
                        {% for section in analysis.exe_details.sections %}
                        <tr>
                            <td>{{ section.name }}</td>
                            <td>{{ section.raw_size }}</td>
                            <td>{{ "%.2f"|format(section.entropy) }}</td>
                            <td>{{ section.characteristics|join(", ") }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <p>No section information available.</p>
                    {% endif %}
                    
                    <h3>Imported Libraries ({{ analysis.exe_details.libraries|length }})</h3>
                    {% if analysis.exe_details.libraries %}
                    <ul>
                        {% for library in analysis.exe_details.libraries %}
                        <li>{{ library }}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>No imported libraries detected.</p>
                    {% endif %}
                    
                    <h3>Interesting Strings</h3>
                    {% if analysis.exe_details.strings_of_interest %}
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Value</th>
                        </tr>
                        {% for string in analysis.exe_details.strings_of_interest %}
                        <tr>
                            <td>{{ string.type }}</td>
                            <td>{{ string.value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <p>No interesting strings detected.</p>
                    {% endif %}
                </div>
                {% endif %}
                
                {% if analysis.pdf_details %}
                <div class="section">
                    <h2>PDF Details</h2>
                    
                    <h3>General Information</h3>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Version</td>
                            <td>{{ analysis.pdf_details.version }}</td>
                        </tr>
                        <tr>
                            <td>Page Count</td>
                            <td>{{ analysis.pdf_details.page_count }}</td>
                        </tr>
                        <tr>
                            <td>Has JavaScript</td>
                            <td>{{ analysis.pdf_details.has_javascript }}</td>
                        </tr>
                        <tr>
                            <td>Has Forms</td>
                            <td>{{ analysis.pdf_details.has_forms }}</td>
                        </tr>
                        <tr>
                            <td>Has Embedded Files</td>
                            <td>{{ analysis.pdf_details.has_embedded_files }}</td>
                        </tr>
                        <tr>
                            <td>Has Auto Actions</td>
                            <td>{{ analysis.pdf_details.has_auto_action }}</td>
                        </tr>
                        <tr>
                            <td>Has Encryption</td>
                            <td>{{ analysis.pdf_details.has_encryption }}</td>
                        </tr>
                        <tr>
                            <td>Has Obfuscation</td>
                            <td>{{ analysis.pdf_details.has_obfuscation }}</td>
                        </tr>
                    </table>
                    
                    {% if analysis.pdf_details.has_javascript and analysis.pdf_details.javascript_code %}
                    <h3>JavaScript Code</h3>
                    <div style="background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow: auto; max-height: 300px;">
                        <pre>{{ analysis.pdf_details.javascript_code|join('\n\n') }}</pre>
                    </div>
                    {% endif %}
                    
                    {% if analysis.pdf_details.has_embedded_files %}
                    <h3>Embedded Files</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Object ID</th>
                        </tr>
                        {% for file in analysis.pdf_details.embedded_files %}
                        <tr>
                            <td>{{ file.filename }}</td>
                            <td>{{ file.object_id }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if analysis.pdf_details.has_auto_action %}
                    <h3>Auto Actions</h3>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Object ID</th>
                        </tr>
                        {% for action in analysis.pdf_details.auto_actions %}
                        <tr>
                            <td>{{ action.type }}</td>
                            <td>{{ action.object_id }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if analysis.pdf_details.urls %}
                    <h3>URLs in Document</h3>
                    <ul>
                        {% for url in analysis.pdf_details.urls %}
                        <li>{{ url }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if analysis.pdf_details.has_suspicious_objects %}
                    <h3>Suspicious Objects</h3>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Pattern</th>
                            <th>Object ID</th>
                        </tr>
                        {% for obj in analysis.pdf_details.suspicious_objects %}
                        <tr>
                            <td>{{ obj.type }}</td>
                            <td>{{ obj.pattern }}</td>
                            <td>{{ obj.object_id }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                </div>
                {% endif %}
                
                <div class="footer">
                    <p>Static Malware Analyzer | Report ID: {{ task_id }} | Generated: {{ report_time }}</p>
                </div>
            </body>
            </html>
            """
            template = jinja2.Template(template_str)
        
        # Generate charts
        malware_score_chart = generate_malware_score_chart(analysis_data.get("malware_score", 0), 
                                                          analysis_data.get("severity", SeverityLevel.UNKNOWN))
        
        # Prepare template data
        template_data = {
            "analysis": analysis_data,
            "report_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "task_id": task_id,
            "malware_score_chart": malware_score_chart
        }
        
        # Render HTML template
        html_content = template.render(**template_data)
        
        # Save HTML to file
        with open(html_path, 'w') as html_file:
            html_file.write(html_content)
        
        logger.info(f"HTML report generated: {html_path}")
        return html_path
    
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")
        
        # Create a basic HTML with error message
        basic_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Static Malware Analysis Report - Error</title>
        </head>
        <body>
            <h1>Static Malware Analysis Report</h1>
            <h2>Error Generating Report</h2>
            <p>An error occurred during report generation: {str(e)}</p>
            <p>Task ID: {task_id}</p>
            <p>Analysis Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </body>
        </html>
        """
        
        with open(html_path, 'w') as html_file:
            html_file.write(basic_html)
        
        return html_path


def generate_json_report(task_id: str, analysis_data: Dict[str, Any]) -> str:
    """
    Generate a JSON report for the analysis results
    """
    # Define the JSON output path
    json_path = os.path.join(settings.REPORTS_DIR, f"{task_id}.json")
    
    try:
        # Add report metadata
        report_data = {
            "report_id": task_id,
            "report_type": "static_analysis",
            "report_time": datetime.utcnow().isoformat(),
            "analysis": analysis_data
        }
        
        # Save JSON to file
        with open(json_path, 'w') as json_file:
            json.dump(report_data, json_file, indent=2, default=str)
        
        logger.info(f"JSON report generated: {json_path}")
        return json_path
    
    except Exception as e:
        logger.error(f"Error generating JSON report: {str(e)}")
        
        # Create a basic JSON with error message
        error_json = {
            "error": str(e),
            "task_id": task_id,
            "report_time": datetime.utcnow().isoformat()
        }
        
        with open(json_path, 'w') as json_file:
            json.dump(error_json, json_file, default=str)
        
        return json_path


def generate_malware_score_chart(malware_score: float, severity: SeverityLevel) -> Optional[str]:
    """
    Generate a base64-encoded PNG chart of the malware score
    """
    try:
        plt.figure(figsize=(8, 4))
        
        # Define colors based on severity
        colors = {
            SeverityLevel.HIGH: '#d9534f',    # Red
            SeverityLevel.MEDIUM: '#f0ad4e',  # Orange
            SeverityLevel.LOW: '#5bc0de',     # Blue
            SeverityLevel.CLEAN: '#5cb85c',   # Green
            SeverityLevel.UNKNOWN: '#777777'  # Gray
        }
        
        # Create gauge chart
        pos = np.arange(0.0, 2*np.pi, 2*np.pi/100)
        bars = plt.bar(
            pos, 
            np.ones_like(pos)*0.5, 
            width=2*np.pi/100,
            alpha=0.2,
            color='lightgray'
        )
        
        # Calculate position for score marker
        score_pos = 2*np.pi * malware_score
        
        # Add score marker
        plt.bar(
            [score_pos], 
            [0.5], 
            width=2*np.pi/50,
            color=colors.get(severity, colors[SeverityLevel.UNKNOWN])
        )
        
        # Add score text
        plt.text(
            0, 0, 
            f"{malware_score:.2f}",
            ha='center',
            va='center',
            fontsize=24,
            color=colors.get(severity, colors[SeverityLevel.UNKNOWN])
        )
        
        # Configure the plot
        plt.axis('equal')
        plt.xlim(0, 2*np.pi)
        plt.ylim(-0.2, 0.6)
        plt.axis('off')
        
        # Add severity label
        plt.figtext(
            0.5, 0.2, 
            f"Severity: {severity.upper()}",
            ha='center',
            fontsize=16,
            color=colors.get(severity, colors[SeverityLevel.UNKNOWN])
        )
        
        # Convert plot to base64 string
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()
        
        return image_base64
    
    except Exception as e:
        logger.error(f"Error generating malware score chart: {str(e)}")
        return None