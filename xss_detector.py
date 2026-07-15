import requests

def check_xss(url):

    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        response = requests.get(url, headers=headers, timeout=5)

        html = response.text.lower()

        dangerous_patterns = [
            '<script>alert(',
            '"><script>',
            "'><script>",
            '<img src=x onerror=',
            '<svg onload=',
            'javascript:alert('
        ]

        found = []

        for pattern in dangerous_patterns:
            if pattern in html:
                found.append(pattern)

        if len(found) == 0:
            return {
                "safe": True,
                "found": []
            }
        else:
            return {
                "safe": False,
                "found": found
            }

    except Exception as e:
        return {
            "safe": False,
            "found": [],
            "error": str(e)
        }