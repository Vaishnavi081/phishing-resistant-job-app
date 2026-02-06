"""
risk_scoring.py - EXACT Risk Scoring Algorithm
Person 1 Responsibility: Implement the exact scoring algorithm from requirements
"""

import re

# Configuration as per requirements
BLACKLISTED_DOMAINS = ['gmai.com', 'gmal.com', 'gmail.cm', 'paypall.com', 'yahooo.com']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
SUSPICIOUS_KEYWORDS = ['urgent', 'crypto', 'paypal', 'western union', 'money transfer']

def has_mx_records(domain):
    """
    Check if domain has MX records
    For MVP: Simulate DNS check with blacklist
    """
    # In real implementation: import dns.resolver
    # For MVP, just check against known bad domains
    return domain not in BLACKLISTED_DOMAINS

def is_suspicious_tld(domain):
    """Check if domain has suspicious TLD"""
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False

def count_suspicious_keywords(text):
    """Count suspicious keywords in text"""
    count = 0
    text_lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            count += 1
    return count

def has_phishing_indicators(url):
    """
    Check for common phishing indicators
    MVP Implementation: Simple checks
    """
    # Check for URL shortening
    shorteners = ['tinyurl.com', 'bit.ly', 'goo.gl']
    for shortener in shorteners:
        if shortener in url:
            return True
    
    # Check for IP address
    if re.match(r'http://\d+\.\d+\.\d+\.\d+', url):
        return True
    
    # Check for excessive special chars
    if len(re.findall(r'[!@#$%^&*()]', url)) > 3:
        return True
    
    return False

def calculate_risk_score(url, domain, description=""):
    """
    EXACT IMPLEMENTATION AS REQUIRED IN PROBLEM SPEC
    Scoring breakdown:
    - Domain checks: 30 pts max
    - URL checks: 40 pts max  
    - Content checks: 30 pts max
    """
    score = 0
    
    # DOMAIN CHECKS (30 pts)
    if not has_mx_records(domain):
        score += 30
    
    if domain in BLACKLISTED_DOMAINS:
        score += 25
    
    if is_suspicious_tld(domain):
        score += 15
    
    # URL CHECKS (40 pts)
    if not url.startswith(('http://', 'https://')):
        score += 20
    
    keyword_count = count_suspicious_keywords(url + " " + description)
    score += min(keyword_count * 5, 20)
    
    # CONTENT CHECKS (30 pts)
    if has_phishing_indicators(url):
        score += 30
    
    # Ensure score doesn't exceed 100
    return min(score, 100)

# ========== TEST FUNCTION ==========
def test_risk_scoring():
    """Test the exact implementation"""
    print("🧪 TESTING EXACT RISK SCORING ALGORITHM")
    print("=" * 60)
    
    # Test Case 1: Fake domain (@gmai.com)
    print("\n✅ Test 1: Fake email domain (@gmai.com)")
    score1 = calculate_risk_score(
        url="https://apply-now.com/job",
        domain="gmai.com",
        description="Software Engineer"
    )
    print(f"   Score: {score1}/100")
    print(f"   Expected: >70 (Auto-reject)")
    print(f"   Result: {'✅ PASS' if score1 > 70 else '❌ FAIL'}")
    
    # Test Case 2: Phishing link
    print("\n✅ Test 2: Phishing link")
    score2 = calculate_risk_score(
        url="http://bit.ly/urgent-crypto-job",
        domain="bit.ly",
        description="URGENT! Earn crypto with PayPal! Western union transfers!"
    )
    print(f"   Score: {score2}/100")
    print(f"   Expected: >85 (High risk)")
    print(f"   Result: {'✅ PASS' if score2 > 85 else '❌ FAIL'}")
    
    # Test Case 3: Safe job
    print("\n✅ Test 3: Safe job posting")
    score3 = calculate_risk_score(
        url="https://careers.microsoft.com/jobs",
        domain="microsoft.com",
        description="Software Engineer position"
    )
    print(f"   Score: {score3}/100")
    print(f"   Expected: <30 (Safe)")
    print(f"   Result: {'✅ PASS' if score3 < 30 else '❌ FAIL'}")
    
    print("\n" + "=" * 60)
    print("🎯 SUCCESS CRITERIA CHECK:")
    print(f"1. Fake @gmai.com rejected: {'✅ YES' if score1 > 70 else '❌ NO'}")
    print(f"2. Phishing link >85: {'✅ YES' if score2 > 85 else '❌ NO'}")
    
    if score1 > 70 and score2 > 85:
        print("\n🎉 ALL SUCCESS CRITERIA MET! 🎉")
    else:
        print("\n⚠️ Some criteria not met")

if __name__ == "__main__":
    test_risk_scoring()