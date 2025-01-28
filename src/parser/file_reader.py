# src/parser/file_reader.py

class TerraformFileReader:
    """
    A class to read and validate Terraform configuration files.
    This is the foundation of our security scanning tool.
    """
    
    def __init__(self):
        self.content = None
        self.filename = None
        self.errors = []
    
    def read_file(self, filepath):
        """
        Reads a Terraform file and stores its content.
        
        Args:
            filepath (str): Path to the Terraform file
            
        Returns:
            bool: True if file was read successfully, False otherwise
        """
        try:
            self.filename = filepath
            with open(filepath, 'r') as file:
                self.content = file.read()
            return True
        except FileNotFoundError:
            self.errors.append(f"File not found: {filepath}")
            return False
        except PermissionError:
            self.errors.append(f"Permission denied: {filepath}")
            return False
        except Exception as e:
            self.errors.append(f"Error reading file {filepath}: {str(e)}")
            return False
    
    def is_terraform_file(self):
        """
        Performs basic validation to check if the file appears to be a Terraform configuration.
        
        Returns:
            bool: True if file appears to be a valid Terraform configuration
        """
        if not self.content:
            return False
        
        # Look for common Terraform syntax patterns
        terraform_patterns = [
            'resource "',
            'provider "',
            'variable "',
            'terraform {'
        ]
        
        return any(pattern in self.content for pattern in terraform_patterns)
    
    def get_content(self):
        """
        Returns the content of the file if it was read successfully.
        
        Returns:
            str: Content of the file or None if file wasn't read
        """
        return self.content
    
    def get_errors(self):
        """
        Returns any errors that occurred during file operations.
        
        Returns:
            list: List of error messages
        """
        return self.errors