import socket

def start_sniffing():
    # Create a raw socket and bind it to the public interface
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind(("192.168.10.180", 0))  # Replace with your IP address
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("Starting packet capture...")

    try:
        while True:
            # Receive a packet
            raw_data, addr = conn.recvfrom(65565)
            print(raw_data)
    except KeyboardInterrupt:
        print("Stopping packet capture.")
    finally:
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conn.close()

# Start sniffing (replace with your correct local IP address)
start_sniffing()
