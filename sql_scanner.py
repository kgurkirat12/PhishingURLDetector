import requests

def check_sql_injection(url):

    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "'--",
        "'#"
    ]

    errors = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "oracle",
        "database error",
        "odbc",
        "sql error"
    ]

    vulnerable = False
    matched_error = ""

    try:

        for payload in payloads:

            test_url = url + payload

            response = requests.get(test_url, timeout=5)

            page = response.text.lower()

            for error in errors:

                if error in page:
                    vulnerable = True
                    matched_error = error
                    break

            if vulnerable:
                break

        return {
            "vulnerable": vulnerable,
            "error": matched_error
        }

    except Exception as e:

        return {
            "vulnerable": False,
            "error": str(e)
        }