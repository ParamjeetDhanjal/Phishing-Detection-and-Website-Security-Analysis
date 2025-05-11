# Phishing and Website Security Checker using VirusTotal API

This project is developed as part of a cybersecurity internship. It is a web-based tool that allows users to check whether a given URL is potentially malicious (phishing) and to evaluate the overall security of a website. The application uses the VirusTotal API and several built-in Python libraries to perform checks and provide real-time analysis.

## Features

- Detects whether a URL is potentially used for phishing
- Analyzes website security through key security headers and HTTPS support
- Provides real-time scanning results using VirusTotal API
- Visual representation of website security with a circular score graph
- User-friendly web interface built with Django

## Technologies Used

- HTML, CSS (Frontend)
- Python with Django (Backend)
- VirusTotal Public API for URL threat intelligence
- 'requests', 'ssl', 'socket', and 'urllib' libraries for security checks

## How It Works

### URL Phishing Checker
1. The user submits a URL on the provided form.
2. The application sends the URL to VirusTotal for analysis.
3. Based on the response:
   - If the URL is marked malicious by any engine, the result is displayed in red with the message **"Warning: Malicious URL Detected. This site is not safe."**
   - If no engine reports it as malicious, the result is shown in green with the message **"Safe URL. No malicious content detected."**

### Website Security Checker
1. The user inputs a website URL.
2. The system performs:
   - HTTPS certificate check
   - Check for 5 important security headers:
     - Content-Security-Policy
     - X-Frame-Options
     - Strict-Transport-Security
     - X-XSS-Protection
     - X-Content-Type-Options
3. The results are shown with:
   - Checklist of which headers are present or missing
   - A circular graph showing the security percentage based on passed checks


### Phishing Check

## Input:
https://suspicious-site.com

## Output:

[Red Box]
Warning: Malicious URL Detected
URL: https://suspicious-site.com
Malicious: Yes

## Input:
https://example.com

## Output:

[Green Box]
Safe URL
URL: https://example.com
Malicious: No

### Website Security Checker

**Input:**
```
https://secure-site.com
```

**Output:**

- ✅ HTTPS is enabled (Certificate by: Let's Encrypt)
- ✅ Content-Security-Policy: Present
- ✅ X-Frame-Options: Present
- ⚠️ Strict-Transport-Security: Missing
- ⚠️ X-XSS-Protection: Missing

**Security Score: 60%**
Displayed inside a circular graph.

## How to Run

1. Clone the repository:
   
   git clone https://github.com/yourusername/Phishing-Detection-and-Website-Security-Analysis.git
   cd
Phishing-Detection-and-Website-Security-Analysis
   

2. Install the required packages:
  
   pip install -r requirements.txt
   

3. Set your VirusTotal API key inside the Django view file:
   python
   API_KEY = "your_virustotal_api_key"
  

4. Run the server:
   
   python manage.py runserver
   

5. Visit `http://localhost:8000` in your browser.

## Project Structure

```
├── myapp/
│   ├── views.py
│   ├── urls.py
│   ├── templates/
│   │   ├── phishing_site.html
│   │   ├── url.html
│   │   ├── Website_checker.html
│   │   └── phishing_info.html
│   └── static/
├── manage.py
└── README.md
```

## Author

Paramjeet Dhanjal  
BSc IT, Mulund College of Commerce  
Cybersecurity Intern

## License

This project is for educational and research purposes only.
