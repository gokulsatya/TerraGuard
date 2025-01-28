# src/report/generator.py

import os
from datetime import datetime
from typing import List, Dict, Any
from collections import Counter

class Colors:
    """Simple class to hold ANSI color codes for console output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class ReportGenerator:
    """
    Enhanced report generator that creates both console and HTML reports.
    This class helps students understand security findings through clear
    visualization and detailed explanations.
    """
    
    def __init__(self, findings: List[Dict[str, Any]], filepath: str):
        self.findings = findings
        self.filepath = filepath
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.statistics = self._calculate_statistics()

    def _calculate_statistics(self) -> Dict[str, Any]:
        """
        Calculates statistics about security findings to help understand
        the overall security posture.
        """
        severity_counts = Counter(finding['severity'] for finding in self.findings)
        total_findings = len(self.findings)
        
        # Group findings by category (based on rule_id prefix)
        categories = Counter()
        for finding in self.findings:
            category = finding['rule_id'].split('_')[0] if '_' in finding['rule_id'] else finding['rule_id']
            categories[category] += 1
        
        return {
            'total_findings': total_findings,
            'severity_counts': dict(severity_counts),
            'categories': dict(categories),
            'has_critical': any(f['severity'] == 'CRITICAL' for f in self.findings)
        }

    def generate_console_report(self):
        """
        Generates a detailed console report with color coding and clear sections.
        This helps students quickly identify and understand security issues.
        """
        # Print summary header
        print(f"\n{Colors.BOLD}Security Scan Report{Colors.ENDC}")
        print(f"Scanned file: {self.filepath}")
        print(f"Scan time: {self.timestamp}")
        print("-" * 50)
        
        # Print statistics
        print(f"\n{Colors.BOLD}Summary Statistics:{Colors.ENDC}")
        print(f"Total findings: {self.statistics['total_findings']}")
        
        if self.statistics['has_critical']:
            print(f"\n{Colors.RED}⚠️ CRITICAL ISSUES FOUND! Immediate attention required!{Colors.ENDC}")
        
        # Print severity breakdown
        print(f"\n{Colors.BOLD}Findings by Severity:{Colors.ENDC}")
        for severity, count in self.statistics['severity_counts'].items():
            color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.RED,
                'MEDIUM': Colors.YELLOW,
                'LOW': Colors.BLUE
            }.get(severity, Colors.BLUE)
            print(f"{color}{severity}: {count}{Colors.ENDC}")
        
        # Print category breakdown
        print(f"\n{Colors.BOLD}Findings by Category:{Colors.ENDC}")
        for category, count in self.statistics['categories'].items():
            print(f"{category}: {count}")
        
        # Print detailed findings
        if self.findings:
            print(f"\n{Colors.BOLD}Detailed Findings:{Colors.ENDC}\n")
            for i, finding in enumerate(self.findings, 1):
                severity_color = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.RED,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.BLUE
                }.get(finding['severity'], Colors.BLUE)
                
                print(f"{Colors.BOLD}Finding #{i}:{Colors.ENDC}")
                print(f"{Colors.BOLD}Rule ID:{Colors.ENDC} {finding['rule_id']}")
                print(f"{Colors.BOLD}Severity:{Colors.ENDC} "
                      f"{severity_color}{finding['severity']}{Colors.ENDC}")
                print(f"{Colors.BOLD}Issue:{Colors.ENDC} {finding['message']}")
                
                if finding['line_number']:
                    print(f"{Colors.BOLD}Line Number:{Colors.ENDC} {finding['line_number']}")
                
                if finding['suggested_fix']:
                    print(f"\n{Colors.BOLD}Suggested Fix:{Colors.ENDC}")
                    print(f"{Colors.BLUE}{finding['suggested_fix']}{Colors.ENDC}")
                
                print("-" * 50)
        else:
            print(f"\n{Colors.GREEN}No security issues found! Your configuration looks good!{Colors.ENDC}")

    def generate_html_report(self):
        """
        Generates a detailed HTML report with formatting and styling.
        This provides a professional-looking report that can be shared with teams.
        """
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>TerraGuard Security Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .critical-alert {{
                    background-color: #dc3545;
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                }}
                .stats-container {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .stat-box {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                }}
                .finding {{
                    border: 1px solid #ddd;
                    padding: 15px;
                    margin-bottom: 15px;
                    border-radius: 5px;
                }}
                .severity-CRITICAL {{ border-left: 5px solid #dc3545; }}
                .severity-HIGH {{ border-left: 5px solid #dc3545; }}
                .severity-MEDIUM {{ border-left: 5px solid #ffc107; }}
                .severity-LOW {{ border-left: 5px solid #17a2b8; }}
                .suggested-fix {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    margin-top: 10px;
                }}
                pre {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    overflow-x: auto;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>TerraGuard Security Report</h1>
                <p>Scanned file: {self.filepath}</p>
                <p>Scan time: {self.timestamp}</p>
            </div>
        """

        # Add critical alert if needed
        if self.statistics['has_critical']:
            html_content += """
            <div class="critical-alert">
                <h2>⚠️ CRITICAL ISSUES FOUND!</h2>
                <p>Immediate attention required! Critical security vulnerabilities have been detected.</p>
            </div>
            """

        # Add statistics
        html_content += """
            <h2>Security Scan Statistics</h2>
            <div class="stats-container">
        """
        
        # Total findings
        html_content += f"""
            <div class="stat-box">
                <h3>Total Findings</h3>
                <p>{self.statistics['total_findings']}</p>
            </div>
        """
        
        # Severity breakdown
        severity_html = "<div class='stat-box'><h3>Findings by Severity</h3>"
        for severity, count in self.statistics['severity_counts'].items():
            severity_html += f"<p>{severity}: {count}</p>"
        severity_html += "</div>"
        html_content += severity_html
        
        # Category breakdown
        category_html = "<div class='stat-box'><h3>Findings by Category</h3>"
        for category, count in self.statistics['categories'].items():
            category_html += f"<p>{category}: {count}</p>"
        category_html += "</div>"
        html_content += category_html + "</div>"
        
        # Add detailed findings
        if self.findings:
            html_content += "<h2>Detailed Findings</h2>"
            for finding in self.findings:
                html_content += f"""
                <div class="finding severity-{finding['severity']}">
                    <h3>Rule: {finding['rule_id']}</h3>
                    <p><strong>Severity:</strong> {finding['severity']}</p>
                    <p><strong>Issue:</strong> {finding['message']}</p>
                """
                
                if finding['line_number']:
                    html_content += f"<p><strong>Line Number:</strong> {finding['line_number']}</p>"
                
                if finding['suggested_fix']:
                    html_content += f"""
                    <div class="suggested-fix">
                        <h4>Suggested Fix:</h4>
                        <pre>{finding['suggested_fix']}</pre>
                    </div>
                    """
                
                html_content += "</div>"
        else:
            html_content += """
            <div class="finding" style="border-left: 5px solid #28a745;">
                <h3>No Security Issues Found!</h3>
                <p>Your configuration appears to follow security best practices.</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        # Save the HTML report
        report_dir = "reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        filename = f"terraguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(report_dir, filename)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
            
        return report_path

    @classmethod
    def generate_report(cls, findings: List[Dict[str, Any]], filepath: str):
        """
        Generates both console and HTML reports for the security findings.
        This provides both immediate feedback and detailed documentation.
        """
        reporter = cls(findings, filepath)
        reporter.generate_console_report()
        html_report_path = reporter.generate_html_report()
        print(f"\n{Colors.BOLD}HTML report generated:{Colors.ENDC} {html_report_path}")