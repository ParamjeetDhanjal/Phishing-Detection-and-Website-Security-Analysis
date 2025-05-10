# Source Code: Phishing and Website Security Checker

This folder contains the source code and dependencies for the Django-based phishing and website security checker tool developed during the cybersecurity internship.

## Folders and Files

### source_code/
Contains the full Django project:
- manage.py: Main file to run the project.
- myproject/: Django settings, URLs, and configuration.
- myapp/: Contains your views, templates, and logic.
  - views.py: Main logic for VirusTotal API, phishing check, and website header analysis.
  - urls.py: Routes URLs to views.
  - templates/myapp/: HTML files (form, result pages).
  - static/myapp/: CSS and image assets.
  - migrations/: Auto-generated database migration files.

### requirements.txt
Lists all the Python packages needed to run the tool.  
Install them using:

pip install -r requirements.txt

## How It Works

### URL Phishing Check
- The user enters a URL.
- The tool sends the URL to VirusTotal API.
- Based on results from antivirus engines, it shows if the site is Safe or Malicious.

### Website Security Header Check
- Checks for HTTPS and 5 important headers:
  - Content-Security-Policy
  - X-Frame-Options
  - Strict-Transport-Security
  - X-XSS-Protection
  - X-Content-Type-Options
- Displays a security checklist and a circular graph score.

## Running the Tool

1. Navigate to source_code/ folder.
2. Install dependencies:

pip install -r requirements.txt

3. Set your VirusTotal API key in views.py.
4. Run the server:

python manage.py runserver

5. Open browser and visit: http://localhost:8000/

## Note
- This tool uses the VirusTotal public API (requires free API key).
- It is for educational and research use only.
