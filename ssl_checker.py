import ssl
import socket


def check_ssl(hostname):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])

        issuer_name = issuer.get("organizationName", "Unknown")

        expiry = cert["notAfter"]

        return {
            "status": "Valid",
            "issuer": issuer_name,
            "expiry": expiry
        }

    except Exception as e:

        return {
            "status": "Invalid",
            "issuer": "-",
            "expiry": "-",
            "error": str(e)
        }