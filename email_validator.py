import re
import ipaddress
import tkinter as tk
from tkinter import messagebox, scrolledtext


# ------------ Email Validation Logic ------------
def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def validate_email(email):
    if len(email) > 254:
        return False, "Email too long (>254 characters)"

    if email.count('@') != 1:
        return False, "Must contain exactly one @ symbol"

    local, domain = email.split('@')

    if not local or not domain:
        return False, "Missing local or domain part"

    if len(local) > 64:
        return False, "Local part too long (>64 characters)"

    if ' ' in email and not email.startswith('"') and not email.endswith('"'):
        return False, "Spaces must be inside quotes"

    if len(email) - email.index('@') <= 6:
        return False, "@ must be at least 6 characters from the end"

    if email[0] == '@':
        return False, "@ can't be the first character"

    if '..' in email or '--' in email or '@@' in email:
        return False, "Consecutive punctuation not allowed"

    local_regex = r"^(?!\.)(?!.*\.\.)(?!.*\.$)[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$"
    if not re.match(local_regex, local):
        return False, "Invalid characters or format in local part"

    if domain.startswith('-') or domain.endswith('-'):
        return False, "Hyphen not allowed at start/end of domain"
    if '_' in domain:
        return False, "Underscore not allowed in domain part"

    ipv4_match = re.match(r"^\[(\d{1,3}(?:\.\d{1,3}){3})\]$", domain)
    if ipv4_match:
        ip = ipv4_match.group(1)
        if not is_valid_ipv4(ip):
            return False, "Invalid IPv4 address"
    else:
        if '.' not in domain:
            return False, "Domain must contain a dot"

        parts = domain.split('.')
        if len(parts[-1]) < 2:
            return False, "Top-level domain must be at least 2 characters"

        domain_regex = r"^[a-zA-Z0-9-]+$"
        for part in parts:
            if not re.match(domain_regex, part):
                return False, f"Invalid domain part: {part}"

    return True, "Valid email"


# ------------ GUI Code Starts Here ------------
def validate_inputs():
    input_text = email_input.get("1.0", tk.END).strip()
    email_list = input_text.splitlines()
    result_output.delete("1.0", tk.END)

    for email in email_list:
        if email.strip() == "":
            continue
        valid, reason = validate_email(email.strip())
        result_output.insert(tk.END, f"{email.strip():40} -> {'✅ Valid' if valid else '❌ Invalid'} ({reason})\n")


# Create window
root = tk.Tk()
root.title("Email Validator")
root.geometry("600x500")
root.resizable(False, False)

# Labels and text areas
title_label = tk.Label(root, text="📧 Email Validator", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

input_label = tk.Label(root, text="Enter one email per line:")
input_label.pack()

email_input = scrolledtext.ScrolledText(root, height=10, width=70, font=("Courier", 10))
email_input.pack(pady=5)

validate_btn = tk.Button(root, text="Validate Emails", command=validate_inputs, bg="#4CAF50", fg="white",
                         font=("Arial", 12))
validate_btn.pack(pady=10)

result_label = tk.Label(root, text="Results:")
result_label.pack()

result_output = scrolledtext.ScrolledText(root, height=12, width=70, font=("Courier", 10))
result_output.pack(pady=5)

# Run the GUI
root.mainloop()
