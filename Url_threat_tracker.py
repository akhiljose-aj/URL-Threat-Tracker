import tkinter as tk
from tkinter import *
from tkinter import messagebox, ttk  # Import ttk for themed widgets
import re
import requests
from urllib.parse import urlparse


def malicious_url(url):
        # Check for known malicious keywords in the URL
        malicious_keywords = ['malware', 'phishing', 'attack', 'exploit', 'virus']
        for keyword in malicious_keywords:
            if keyword in url:
                return True

        if url == 'https://drive.google.com/':
            return False

        # Check if the URL uses an IP address instead of a domain name
        if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            return True

        # Check if the URL has an excessive number of subdomains
        if url.count('.') >= 4:
            return True

        # Check if the URL's domain is a known free hosting or suspicious domain
        known_suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.to',
                                    '000webhostapp.com', '.cz', '.ie','.ac']
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        for suspicious_domain in known_suspicious_domains:
            if suspicious_domain in domain:
                return True

        # Check for unusual characters in the URL
        if re.search(r'[^\w\s:/.-]', url):
            return True

        # Check for URL shorteners
        if re.match(r'^https?://(bit\.ly|t\.co|ow\.ly|tinyurl\.com|is\.gd|shorte\.st|goo\.gl|cli\.gs|tr\.im)', url):
            return True
        # >Suspicious TLD Check: Check if the top-level domain (TLD) of the URL is suspicious.
        suspicious_tlds = ['.onion', '.xyz', '.biz', '.info']
        for tld in suspicious_tlds:
            if url.endswith(tld):
                return True
        # >Check for Redirects: Check if the URL redirects to another domain.
        response = requests.head(url, allow_redirects=True)
        if response.url != url:
            return True

        # >Check for Long URLs: Some malicious URLs can be excessively long.
        max_url_length = 2100
        if len(url) > max_url_length:
            return True

        # >Blacklist Check: Maintain a list of known malicious URLs or domains and
        # check if the input URL matches any of them.

        blacklist = ['https://malicious.com', 'http://evil.org',
                     'http://subtitleseeker.com', 'http://financereports.co', 'http://tryteens.com',
                     'http://iranact.co', 'http://creativebookmark.com','http://ffupdate.org', 'http://vegweb.com','https://cek.ac.in/',
                     'http://vegweb.com', 'http://delgets.com', 'http://totalpad.com','http://cek.ac.in/']
        if url in blacklist:
            return True

        # Check for Suspicious Parameters: Check if the URL contains suspicious query parameters or fragments.
        if re.search(r'[?#&](cmd=|shell=|exec=|download=)', url):
            return True

        return False

def check_url():
    url = url_entry.get()
    u=len(url)
    if u<1:
        messagebox.showinfo("Invalid URL!",f" please insert a valid URL.")

    elif not url.startswith("https://" or "http://"):
        messagebox.showinfo("Invalid URL!", f" Please insert a valid URL.\n https:// or www is missing.")
    elif malicious_url(url):
        messagebox.showwarning("Threat Found", f"The URL '{url}'\n May be MALICIOUS. BROWSE AT YOUR OWN RISK!")
    else:
        messagebox.showinfo("No Threat Found", f"The URL '{url}'\n Is likely NOT mailicious.")

# Create the main window
window = tk.Tk()
window.title("URL SAFETY CHECKER")
#Disable the resizable Property
window.resizable(False, False)
#Adding image icon
photo = PhotoImage(file="urlimg.png")
window.iconphoto(False, photo)
# Create and configure the URL entry field
url_label = tk.Label(window,width=51, text="Enter the URL to check:",font="calibri 10 bold")
url_label.pack(pady=10)  # Add some padding to the top

url_entry = tk.Entry(window, width=50)
url_entry.pack(pady=5)  # Add padding between the entry and button

# Create and configure the Check button with a themed style
style = ttk.Style()
style.configure("TButton", padding=10, font =('calibri', 10, 'bold'),foreground = 'red')  # Increase button padding
check_button = ttk.Button(window, text="Check URL", command=check_url, style="TButton",cursor='hand2',)
check_button.pack(pady=10)

# Start the GUI main loop
window.mainloop()