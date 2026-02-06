"""
email_verifier.py - Email Domain Verification
Person 1 Responsibility: Validate employer emails with domain checks
"""

import re

# Common fake domains
FAKE_DOMAINS = [
    'gmai.com', 'gmal.com', 'gmail.cm', 'gmail.co',
    'yahooo.com', 'outlok.com', 'hotmal.com',
    'micorsoft.com', 'paypall.com', 'facebok.com'
]

def validate_email_format(email):
    """Basic email format validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def extract_domain(email):
    """Extract domain from email"""
    if '@' not in email:
        return None
    return email.split('@')[-1].lower()

def is_fake_domain(domain):
    """Check if domain is known fake"""
    return domain in FAKE_DOMAINS

def verify_employer_email(email):
    """
    Verify employer email domain
    Returns: (is_valid, message)
    """
    if not email:
        return False, "Email is required"
    
    # Check format
    if not validate_email_format(email):
        return False, "Invalid email format"
    
    # Extract domain
    domain = extract_domain(email)
    if not domain:
        return False, "Could not extract domain"
    
    # Check for fake domains
    if is_fake_domain(domain):
        # Suggest correction
        suggestions = {
            'gmai.com': 'gmail.com',
            'gmal.com': 'gmail.com',
            'paypall.com': 'paypal.com',
            'yahooo.com': 'yahoo.com'
        }
        suggestion = suggestions.get(domain, 'a valid domain')
        return False, f"Domain appears fake. Did you mean @{suggestion}?"
    
    # Check for free email providers (optional for employers)
    free_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
    if domain in free_domains:
        return False, "Please use a company email address, not a free email provider"
    
    return True, f"Email domain '{domain}' is valid"

def quick_email_check(email):
    """
    Quick validation for forms
    Returns simple boolean
    """
    if not email or '@' not in email:
        return False
    
    domain = email.split('@')[-1].lower()
    return domain not in FAKE_DOMAINS

# ========== TEST FUNCTION ==========
def test_email_verification():
    """Test email verification"""
    print("🧪 TESTING EMAIL VERIFICATION")
    print("=" * 60)
    
    test_emails = [
        ("hr@gmai.com", False),      # Fake domain
        ("careers@microsoft.com", True),  # Valid
        ("recruiter@gmail.com", False),   # Free email
        ("invalid-email", False),    # Invalid format
        ("admin@company.xyz", True), # Valid
        ("scam@paypall.com", False) # Fake domain
    ]
    
    for email, should_be_valid in test_emails:
        is_valid, message = verify_employer_email(email)
        result = "✅ PASS" if is_valid == should_be_valid else "❌ FAIL"
        print(f"📧 {email}")
        print(f"   Expected: {'Valid' if should_be_valid else 'Invalid'}")
        print(f"   Actual: {'Valid' if is_valid else 'Invalid'} - {message}")
        print(f"   Result: {result}\n")
    
    print("=" * 60)
    print("✅ Success Criteria: @gmai.com → REJECTED")

if __name__ == "__main__":
    test_email_verification()