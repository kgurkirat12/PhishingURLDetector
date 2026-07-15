import requests
import time


def scan_url(url):
    """
    Scan a website and return basic information.
    """

    result = {}

    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        start = time.time()

        response = requests.get(
            url,
            headers=headers,
            timeout=5,
            allow_redirects=True
        )

        end = time.time()

        result["status"] = "Reachable"
        result["status_code"] = response.status_code
        result["response_time"] = round(end - start, 2)
        result["server"] = response.headers.get("Server", "Not Available")
        result["final_url"] = response.url
        result["content_type"] = response.headers.get(
            "Content-Type",
            "Unknown"
        )

    except requests.exceptions.Timeout:
        result["status"] = "Timeout"
        result["error"] = "The website took too long to respond."

    except requests.exceptions.ConnectionError:
        result["status"] = "Connection Failed"
        result["error"] = "Unable to connect to the website."

    except Exception as e:
        result["status"] = "Error"
        result["error"] = str(e)

    return result