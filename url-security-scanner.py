import requests
import re

def scan_url(url):
    try:
        # Send an HTTP GET request to the URL
        response = requests.get(url, verify=True, allow_redirects=True)
        
        # Check the HTTP status code for success (200 OK)
        if response.status_code != 200: return "HTTP Error: {}".format(response.status_code)

        # Check the response content for specific keywords or patterns
        if "malicious_keyword" in response.text: return "This URL may be malicious."
        if "phishing_keyword" in response.text: return "This URL may be a phishing attempt."
    
        # Additional security checks
        final_url = response.url
        content_type = response.headers.get('Content-Type')

        # SSL/TLS validation
        if not final_url.startswith("https://"): return "Not a secure HTTPS connection."

        # Content-Type validation
        if 'text/html' not in content_type: return "Invalid Content-Type: {}".format(content_type)

        # Robots.txt analysis (optional)
        robots_url = final_url + "/robots.txt"
        robots_response = requests.get(robots_url)
        robots_content = robots_response.text
        # Analyze robots.txt content

        # Suspicious URL patterns (optional)
        if re.search(r'suspicious_pattern', final_url): return "Suspicious URL detected."

        return "This URL appears to be safe."
            
    except requests.exceptions.RequestException as e:
        return "Error: {}".format(str(e))

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    result = scan_url(url)
    print(result)
