import socket
import ipaddress
import os
from tqdm import tqdm  # Progress bar library

def validate_ip(ip):
    """
    Verifies if the provided string is a valid IPv4 or IPv6 address.

    Args:
        ip (str): The string to validate as an IP address.

    Returns:
        ipaddress.IPv4Address or ipaddress.IPv6Address: If the address is valid,
            returns the corresponding IP address object.
        False: If the address is not valid.
    """
    try:
        return ipaddress.ip_address(ip)  # Attempts to convert the string to an IP address object
    except ValueError:
        return False  # Returns False if the conversion fails (invalid address)


def validate_ports(port_string):
    """
    Validates the port input string.  Accepts single ports,
    comma-separated lists of ports (e.g., "80,443,8080"),
    or the keyword "all" to indicate all ports (1-65535).

    Args:
        port_string (str): The string containing the ports to validate.

    Returns:
        list: A list of integers representing the valid ports,
              or False if the input is not valid.
    """
    try:
        if port_string.strip().lower() == "all":
            return list(range(1, 65536))  # Returns a list with all ports from 1 to 65535
            # strip() removes leading/trailing whitespace, lower() converts to lowercase for case-insensitive comparison

        port_list = port_string.split(",")  # Splits the string into a list of strings, using comma as delimiter
        ports = []  # Initializes an empty list to hold the validated ports
        for port in port_list:
            port = port.strip()  # Removes whitespace from each individual port string
            if not port.isdigit():
                raise ValueError(f"'{port}' is not a valid number.")  # If the port is not a number, raises an exception
            port_num = int(port)  # Converts the port string to an integer
            if not (1 <= port_num <= 65535):
                raise ValueError(f"Port {port_num} is out of valid range (1-65535).")  # Checks if the port is within the valid range
            ports.append(port_num)  # Adds the validated port to the list
        return ports  # Returns the list of validated ports
    except ValueError as e:
        print("Error:", e)  # Prints the error message
        return False  # Returns False in case of an error


def validate_num_packets(num_packets):
    """
    Verifies that the provided number of packets is a positive integer.

    Args:
        num_packets (str): The string to validate as the number of packets.

    Returns:
        int: The number of packets as an integer, if valid.
        False: If the input is not valid.
    """
    try:
        value = int(num_packets)  # Attempts to convert the string to an integer
        if value <= 0:
            raise ValueError("Number of packets must be greater than zero.")  # Checks if the number is positive
        return value  # Returns the number of packets as an integer
    except ValueError as e:
        print("Error:", e)  # Prints the error message
        return False  # Returns False in case of an error

# Generates a 1KB packet filled with random data
def generate_packet():
    """
    Generates a 1KB (1024-byte) data packet filled with random data.

    Returns:
        bytes: A bytes object containing 1024 bytes of random data.
    """
    return os.urandom(1024)  # Uses os.urandom() to generate cryptographically secure random data


def send_udp_packets(ip, ports, num_packets):
    """
    Sends UDP packets to the specified IP address and ports.

    Args:
        ip (str): The destination IP address.
        ports (list): A list of port numbers to send packets to.
        num_packets (int): The number of packets to send to each port.
    """
    val_ip = validate_ip(ip)  # Validates the IP address
    if val_ip is False:
        print("Invalid IP address.")
        return  # Exits the function if the IP is invalid

    # Determine the address family (IPv4 or IPv6) based on the IP version
    family = socket.AF_INET if val_ip.version == 4 else socket.AF_INET6    
    sock = socket.socket(family, socket.SOCK_DGRAM)  # Creates a UDP socket object

    try:
        # Iterates over the list of ports
        for port in ports:
            # Creates a progress bar for each port
            for _ in tqdm(range(num_packets), desc=f"Sending to {ip}:{port}", leave=False):   #_ placeholder for a variable that is not used inside the loop
                packet = generate_packet()  # Generates the data packet
                sock.sendto(packet, (ip, port))  # Sends the packet to the specified IP and port
                # tqdm handles the progress bar, desc provides a description, leave=False prevents the bar from staying after completion
            print(f"Finished sending packets to {ip}:{port}")  # Prints a message after sending packets to each port
    except Exception as e:
        print(f"Error while sending: {e}")  # Catches and prints any exceptions during sending
    finally:
        sock.close()  # Closes the socket in the finally block to ensure it's closed even if exceptions occur


# Prompts the user to enter a valid IP address
while True:
    ip = input("Enter a valid IP address: ")
    validated_ip = validate_ip(ip)  # Validates the entered IP
    if validated_ip:
        break  # Exits the loop if the IP is valid
    print("Invalid IP address. Please try again.")  # Otherwise, prints an error message and repeats

# Prompts the user to enter one or more ports, or "all"
while True:
    port_input = input("Enter one or more ports (comma-separated), or type 'all' for all ports: ")
    validated_ports = validate_ports(port_input)  # Validates the port input
    if validated_ports:
        # If the user entered "all", prompts for confirmation
        if len(validated_ports) == 65535:
            confirm = input("You selected ALL ports (1-65535). This may send a large amount of data. Continue? (yes/no): ").lower()
            if confirm != "yes":
                print("Cancelled.")
                exit()  # Exits the program if the user doesn't confirm
        break  # Exits the loop if the ports are valid
    print("Invalid ports. Please try again.")  # Otherwise, prints an error and repeats

# Prompts the user to enter the number of packets to send
while True:
    num_input = input("Enter the number of packets to send per port: ")
    num_packets = validate_num_packets(num_input)  # Validates the number of packets
    if num_packets:
        break  # Exits the loop if the number is valid
    print("Invalid number. Please try again.")  # Otherwise, prints an error and repeats

# Calls the function to send the UDP packets with the provided parameters
send_udp_packets(ip, validated_ports, num_packets)
