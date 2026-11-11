import socket

# Configuration
BUFFER_SIZE = 1024
TIMEOUT = 5

# Common services
SERVICES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    8080: "HTTP"
}


def create_connection(host, port):
    """Create a TCP connection to the specified service."""

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(TIMEOUT)
    connection.connect((host, port))

    return connection


def send_http_request(connection, host):
    """Send an HTTP HEAD request to a web server."""

    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    connection.sendall(request.encode("utf-8"))


def receive_banner(connection):
    """Receive banner data from the service."""

    return connection.recv(BUFFER_SIZE)


def decode_banner(data):
    """Decode received bytes into readable text."""

    return data.decode("utf-8", errors="ignore").strip()


def extract_first_line(banner):
    """Extract the first main line of the banner."""

    lines = banner.splitlines()

    if lines:
        return lines[0].strip()

    return None


def identify_service(port):
    """Identify the service associated with a port."""

    return SERVICES.get(port, "Unknown Service")


def identify_os(banner):
    """Identify the operating system from disclosed banner information."""

    if not banner:
        return "Not identified"

    os_signatures = {
        "Ubuntu": ["Ubuntu"],
        "Debian": ["Debian"],
        "Windows": [
            "Windows",
            "Microsoft-IIS",
            "Microsoft-HTTPAPI"
        ],
        "CentOS": ["CentOS"],
        "FreeBSD": ["FreeBSD"],
        "Linux": ["Linux"]
    }

    for os_name, signatures in os_signatures.items():

        for signature in signatures:

            if signature.lower() in banner.lower():

                if signature in ["Microsoft-IIS", "Microsoft-HTTPAPI"]:
                    return "Likely Windows (based on server signature)"

                return os_name

    return "Not disclosed in banner"


def grab_banner(host, port):
    """Connect to a service and retrieve its banner."""

    try:

        with create_connection(host, port) as connection:

            if port in [80, 8080]:
                send_http_request(connection, host)

            data = receive_banner(connection)

            banner = decode_banner(data)

            if not banner:
                return None, None

            first_line = extract_first_line(banner)

            return first_line, banner

    except socket.timeout:
        return "TIMEOUT", None

    except ConnectionRefusedError:
        return "CONNECTION REFUSED", None

    except OSError:
        return "CONNECTION ERROR", None


def display_result(port, result, full_banner):
    """Display discovered service information."""

    print("\n" + "-" * 45)

    print(f"Port: {port}")

    print(f"Service: {identify_service(port)}")

    if result is None:

        print("Banner: No banner received")
        print("Operating System: Not identified")

    elif result in [
        "TIMEOUT",
        "CONNECTION REFUSED",
        "CONNECTION ERROR"
    ]:

        print(f"Status: {result}")
        print("Operating System: Not identified")

    else:

        print(f"Banner: {result}")

        operating_system = identify_os(full_banner)

        print(f"Operating System: {operating_system}")

    print("-" * 45)


def main():
    """Run the Banner Grabbing Tool."""

    host = input("Enter target IP address: ").strip()

    ports = [21, 22, 80, 8080]

    print("\nStarting Banner Grabbing Tool")

    print("=" * 45)

    for port in ports:

        print(f"\nScanning port {port}...")

        result, full_banner = grab_banner(host, port)

        display_result(port, result, full_banner)

    print("\nBanner Grabbing Completed.")


if __name__ == "__main__":
    main()