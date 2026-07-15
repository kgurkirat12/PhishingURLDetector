import socket

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}


def scan_ports(host):
    """
    Scan common ports of a website/server.
    Returns a list of open ports.
    """

    open_ports = []

    try:
        for port, service in COMMON_PORTS.items():

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            try:
                result = s.connect_ex((host, port))

                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": service
                    })

            finally:
                s.close()

    except Exception:
        # Return empty list if scanning fails
        return []

    return open_ports