# src/report/generator.py

class Colors:
    """Simple class to hold ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class ReportGenerator:
    """Generates formatted security reports with color coding"""
    
    @staticmethod
    def generate_report(findings):
        """
        Generates a colored report from security findings
        
        Args:
            findings (list): List of security findings
            
        Returns:
            None (prints to console)
        """
        if not findings:
            print(f"{Colors.GREEN}No security issues found! Your configuration looks good!{Colors.ENDC}")
            return
            
        print(f"\n{Colors.BOLD}Found {len(findings)} potential security issues:{Colors.ENDC}\n")
        
        for finding in findings:
            # Print severity with color based on level
            severity_color = {
                "HIGH": Colors.RED,
                "MEDIUM": Colors.YELLOW,
                "LOW": Colors.BLUE
            }.get(finding['severity'], Colors.BLUE)
            
            print(f"{Colors.BOLD}Issue:{Colors.ENDC} {finding['message']}")
            print(f"{Colors.BOLD}Severity:{Colors.ENDC} "
                  f"{severity_color}{finding['severity']}{Colors.ENDC}")
            
            if finding['line_number']:
                print(f"{Colors.BOLD}Line Number:{Colors.ENDC} {finding['line_number']}")
            
            if finding['suggested_fix']:
                print(f"{Colors.BOLD}Suggested Fix:{Colors.ENDC}")
                print(f"{Colors.BLUE}{finding['suggested_fix']}{Colors.ENDC}")
            
            print("-" * 50)