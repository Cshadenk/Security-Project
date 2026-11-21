"""
xss_utils.py - Cross-Site Scripting (XSS) protection (Raghad).

  SECURE_MODE = False -> comments are shown exactly as stored (VULNERABLE)
  SECURE_MODE = True  -> comments are cleaned with a tag whitelist (SECURE)
"""
import bleach

# Only these formatting tags are kept in comments
ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br"]


def sanitize_comment(text):
    return bleach.clean(text, tags=ALLOWED_TAGS, attributes={}, strip=True)
