#!/usr/bin/env python3

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import tempfile
import json
import subprocess
import shutil
from pathlib import Path
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security scanner configurations
TOOLS = {
    'bandit': {
        'command': ['bandit', '-f', 'json', '-'],
        'stdin': True,
        'description': 'Python AST security scanner'
    },
    'semgrep': {
        'command': ['semgrep', '--json', '--config=auto', '-'],
        'stdin': True,
        'description': 'Multi-language security patterns'
    },
    'safety': {
        'command': ['safety', 'check', '--json', '--stdin'],
        'stdin': True,
        'description': 'Python dependency vulnerability scanner'
    }
}

def check_tool_availability():
    """Check which security tools are installed and available"""
    available_tools = {}
    
    for tool_name, config in TOOLS.items():
        try:
            result = subprocess.run(
                [config['command'][0], '--help'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            available_tools[tool_name] = {
                'available': result.returncode == 0,
                'description': config['description']
            }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available_tools[tool_name] = {
                'available': False,
                'description': config['description']
            }
    
    return available_tools

def run_security_scan(code, tools_to_run=None, filename='uploaded_code.py'):
    """Run security scans using available tools"""
    if tools_to_run is None:
        tools_to_run = ['bandit', 'semgrep']
    
    results = {
        'findings': [],
        'tool_results': {},
        'summary': {'high': 0, 'medium': 0, 'low': 0},
        'total_lines': len(code.split('\n')),
        'filename': filename,
        'scan_timestamp': None
    }
    
    available_tools = check_tool_availability()
    
    for tool_name in tools_to_run:
        if tool_name not in available_tools or not available_tools[tool_name]['available']:
            logger.warning(f"Tool {tool_name} not available, skipping")
            continue
            
        try:
            tool_config = TOOLS[tool_name]
            result = subprocess.run(
                tool_config['command'],
                input=code,
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0 or result.stdout:
                # Parse tool-specific output
                if tool_name == 'bandit':
                    findings = (result.stdout)
                elif tool_name == 'semgrep':
                    findings = parse_semgrep_output(result.stdout)
                elif tool_name == 'safety':
                    findings = parse_safety_output(result.stdout)
                else:
                    findings = []
                
                results['tool_results'][tool_name] = {
                    'success': True,
                    'findings_count': len(findings),
                    'raw_output': result.stdout
                }
                results['findings'].extend(findings)
            else:
                results['tool_results'][tool_name] = {
                    'success': False,
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            results['tool_results'][tool_name] = {
                'success': False,
                'error': 'Scan timeout'
            }
        except Exception as e:
            results['tool_results'][tool_name] = {
                'success': False,
                'error': str(e)
            }
    
    # Calculate summary
    for finding in results['findings']:
        severity = finding['severity'].lower()
        if severity in results['summary']:
            results['summary'][severity] += 1
    
    # Calculate security score
    weighted_issues = (results['summary']['high'] * 3 + 
                      results['summary']['medium'] * 2 + 
                      results['summary']['low'] * 1)
    score = max(0, min(100, 100 - (weighted_issues * 8)))
    results['security_score'] = round(score)
    
    return results

def parse_bandit_output(output):
    """Parse Bandit JSON output into standardized format"""
    findings = []
    try:
        data = json.loads(output)
        for result in data.get('results', []):
            findings.append({
                'tool': 'bandit',
                'name': result.get('test_name', 'Unknown'),
                'severity': map_bandit_severity(result.get('issue_severity', 'LOW')),
                'line': result.get('line_number', 1),
                'code': result.get('code', '').strip(),
                'description': result.get('issue_text', ''),
                'category': result.get('test_id', 'unknown'),
                'confidence': result.get('issue_confidence', 'UNDEFINED')
            })
    except json.JSONDecodeError:
        logger.error("Failed to parse Bandit output")
    
    return findings

def parse_semgrep_output(output):
    """Parse Semgrep JSON output into standardized format"""
    findings = []
    try:
        data = json.loads(output)
        for result in data.get('results', []):
            findings.append({
                'tool': 'semgrep',
                'name': result.get('check_id', 'Unknown').split('.')[-1],
                'severity': map_semgrep_severity(result.get('extra', {}).get('severity', 'INFO')),
                'line': result.get('start', {}).get('line', 1),
                'code': result.get('extra', {}).get('lines', '').strip(),
                'description': result.get('extra', {}).get('message', ''),
                'category': result.get('check_id', '').split('.')[0] if '.' in result.get('check_id', '') else 'unknown'
            })
    except json.JSONDecodeError:
        logger.error("Failed to parse Semgrep output")
    
    return findings

def parse_safety_output(output):
    """Parse Safety JSON output into standardized format"""
    findings = []
    try:
        data = json.loads(output)
        for vuln in data:
            findings.append({
                'tool': 'safety',
                'name': f"Vulnerable dependency: {vuln.get('package_name', 'Unknown')}",
                'severity': 'high',  # All dependency vulns are high
                'line': 1,  # Dependencies don't have line numbers
                'code': f"{vuln.get('package_name', 'Unknown')} {vuln.get('installed_version', '')}",
                'description': vuln.get('advisory', 'Known security vulnerability'),
                'category': 'dependencies'
            })
    except json.JSONDecodeError:
        logger.error("Failed to parse Safety output")
    
    return findings

def map_bandit_severity(severity):
    """Map Bandit severity to our standard levels"""
    mapping = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
    return mapping.get(severity.upper(), 'medium')

def map_semgrep_severity(severity):
    """Map Semgrep severity to our standard levels"""
    mapping = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}
    return mapping.get(severity.upper(), 'medium')

@app.route('/')
def index():
    """Serve the main HTML interface"""
    return send_from_directory('.', 'devsec_dash.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    available_tools = check_tool_availability()
    return jsonify({
        'status': 'healthy',
        'tools': available_tools,
        'version': '3.0'
    })

@app.route('/scan', methods=['POST'])
def scan_code():
    """Main scanning endpoint - supports both code and file uploads"""
    try:
        # Handle file upload
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Read file content
            code = file.read().decode('utf-8')
            filename = file.filename
            
            tools = request.form.get('tools', 'bandit,semgrep').split(',')
            
        # Handle JSON data
        else:
            data = request.get_json()
            if not data or 'code' not in data:
                return jsonify({'error': 'No code provided'}), 400
            
            code = data['code']
            filename = data.get('filename', 'uploaded_code.py')
            tools = data.get('tools', ['bandit', 'semgrep'])
        
        if not code.strip():
            return jsonify({'error': 'Empty code provided'}), 400
        
        # Run security scan
        logger.info(f"Running security scan on {filename} with tools: {tools}")
        results = run_security_scan(code, tools, filename)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/scan-folder', methods=['POST'])
def scan_folder():
    """Scan entire project folder and stream results"""
    
    def generate_scan_results():
        try:
            if 'folder' not in request.files:
                yield f'data: {json.dumps({"error": "No folder provided"})}\n\n'
                return
            
            files = request.files.getlist('folder')
            tools = request.form.get('tools', 'bandit,semgrep').split(',')
            
            logger.info(f"Streaming scan for {len(files)} files with tools: {tools}")
            
            # Patterns to ignore
            ignore_patterns = [
                '.venv/', 'venv/', 'node_modules/', '__pycache__/', '.git/', 'build/', 'dist/'
            ]
            
            def should_ignore(filename):
                return any(p in filename for p in ignore_patterns)

            code_files = [f for f in files if f.filename and not should_ignore(f.filename) and f.filename.endswith(('.py', '.js', '.php', '.java', '.rb', '.go', '.cpp', '.c', '.cs'))]
            
            total_files = len(code_files)
            yield f'data: {json.dumps({"type": "status", "total_files": total_files})}'

            for i, file in enumerate(code_files):
                try:
                    code = file.read().decode('utf-8', errors='ignore')
                    
                    if not code.strip():
                        logger.warning(f"Skipping empty file: {file.filename}")
                        continue

                    file_results = run_security_scan(code, tools, file.filename)
                    
                    # Yield result for this file
                    yield f'data: {json.dumps({"type": "finding", "file": file.filename, "results": file_results, "progress": (i + 1) / total_files * 100})}'

                except Exception as e:
                    logger.error(f"Error scanning {file.filename}: {str(e)}")
                    yield f'data: {json.dumps({"type": "error", "file": file.filename, "error": str(e)})}\n\n'

            yield f'data: {json.dumps({"type": "done"})}'

        except Exception as e:
            logger.error(f"Folder scan streaming error: {str(e)}")
            yield f'data: {json.dumps({"error": str(e)})}\n\n'

    return app.response_class(generate_scan_results(), mimetype='text/event-stream')


@app.route('/tools')
def list_tools():
    """List available security tools"""
    return jsonify({
        'available_tools': check_tool_availability(),
        'supported_tools': list(TOOLS.keys())
    })

if __name__ == '__main__':
    # Check tool availability on startup
    available = check_tool_availability()
    logger.info("Tool availability check:")
    for tool, status in available.items():
        logger.info(f"  {tool}: {'✓' if status['available'] else '✗'}")
    
    print("\n🛡️ DevSec Dash Backend Server")
    print("=" * 40)
    print(f"🌐 Frontend: http://localhost:8080")
    print(f"🔧 API Health: http://localhost:8080/health")
    print(f"📊 Tools Status: http://localhost:8080/tools")
    print("=" * 40)
    
    app.run(host='localhost', port=8080, debug=True)