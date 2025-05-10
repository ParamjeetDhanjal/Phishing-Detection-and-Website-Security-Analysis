from django.shortcuts import render
from django.http import HttpResponse
import requests
import socket
import ssl
from urllib.parse import urlparse

def phishing_site(request):
    return render(request,'myapp/phishing_site.html')
def url_site(request):
    return render(request,'myapp/url.html')
def website_site(request):
    return render(request,'myapp/Website_checker.html')
def phished(request):
    return render(request,'myapp/phishing_info.html')


def check_url_view(request):
    result = None
    url = None

    API_KEY = 'your_api_key'

    if request.method == 'POST':
        url = request.POST.get('url')
        headers = {
            "x-apikey": API_KEY
        }
        data = {"url": url}

        # Submit URL to VirusTotal
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]

            # Get analysis report using scan ID
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers
            )

            if analysis_response.status_code == 200:
                stats = analysis_response.json()['data']['attributes']['stats']
                result = "Yes" if stats.get('malicious', 0) > 0 else "No"
            else:
                result = "Error retrieving analysis report."
        else:
            result = "Error submitting URL."

    return render(request, 'myapp/url.html', {'result': result, 'url': url})

def check_website_security(request):
    result = ""
    score = 0  # final percentage score
    total_checks = 6  # total number of checks we're performing
    passed = 0

    if request.method == 'POST':
        url = request.POST.get('url')
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path
            port = 443

            # Check HTTPS/SSL
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        issuer = cert.get('issuer', [['Unknown']])[0][0][1]
                        result += f"✅ HTTPS is enabled (Certificate by: {issuer})<br>"
                        passed += 1
            except:
                result += "❌ HTTPS not enabled or unreachable.<br>"

            # Check Security Headers
            headers = requests.get(url, timeout=5).headers
            sec_headers = [
                'Content-Security-Policy', 
                'X-Frame-Options', 
                'Strict-Transport-Security', 
                'X-XSS-Protection', 
                'X-Content-Type-Options'
            ]
            for h in sec_headers:
                if h in headers:
                    result += f"✅ {h}: Present<br>"
                    passed += 1
                else:
                    result += f"⚠️ {h}: Missing<br>"

            score = int((passed / total_checks) * 100)

        except Exception as e:
            result = f"❌ Error: {str(e)}"
            score = 0

    return render(request, 'myapp/Website_checker.html', {'result': result, 'score': score})
