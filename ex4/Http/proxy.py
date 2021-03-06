import threading
import socket
import struct
import sys
import subprocess
import os


class Proxy(threading.Thread):
    """Represents a proxy connection"""

    internal_network = '10.1.1.3'  # enp0s8 interface
    external_network = '10.1.2.3'  # enp0s9 interface

    proxy_dev = '/sys/class/fw/proxy/set_port'

    user_handler = '../user/main'
    conn_arg = 'show_conns'

    def __init__(self, conn, adrr):
        super(Proxy, self).__init__()
        self.client_sock = conn  # The client_end communicates with the client (and imitates the server functionality)
        self.server_sock = None  # The server_end communicates with the server (and imitates the client functionality)
        self.src = adrr
        self.dst = None
        self.done = False
        self.client_thread = None
        self.server_thread = None

    def send_port(self, proxy_port):
        """ Sends to the firewall client's proxy port """
        
        print('Proxy: port = {}'.format(proxy_port))

        client_ip = socket.inet_aton(self.src[0])
        client_port = self.src[1]
        
        # endianness byte order considerations
        pack = struct.pack('<HH', client_port, proxy_port) if sys.byteorder == 'little' else struct.pack('>HH', client_port, proxy_port)
        buf = client_ip + pack

        with open(self.proxy_dev, 'wb') as file:
            file.write(buf)

    def get_dest(self):
        """ Gets the destination of the connection from the firewall (the actual server details) """
        
        dir_path = os.path.dirname(os.path.abspath(__file__))
        user_path = dir_path + '/' + self.user_handler
        print('User path: {}'.format(user_path))
        
        p = subprocess.run([user_path, self.conn_arg], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True)
        connections = p.stdout.splitlines()[1:]
        print('src: ', self.src)
        for connection in connections:
            c_ip, s_ip, c_port, s_port, status = connection.split()
            if c_ip == self.src[0] and int(c_port) == self.src[1]:
                self.dst = (s_ip, int(s_port))
        print('dst: ', self.dst)

    def start_proxy(self):
        # Creating a TCP client
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.external_network, 0))
        self.server_sock = sock

        # Send the dynamically allocated port to the firewall
        srv_addr = sock.getsockname()
        self.send_port(srv_addr[1])

        # Connect to the actual server
        self.get_dest()
        sock.connect(self.dst)
        
    def collect_message(self, sock):
        ''' Collects the message from a socket'''
        
        message = ''
        chunk_size = 512
        
        while True:
            chunk = sock.recv(chunk_size)
            message += chunk.decode()
            if len(chunk) < chunk_size:
                break
            
        return message

    def client_logic(self):
        pass

    def server_logic(self):
        pass

    def run(self):
        # Starts the proxy connection
        self.start_proxy()
        # Creates threads for handling two sides
        self.client_thread = threading.Thread(target=self.client_logic)
        self.server_thread = threading.Thread(target=self.server_logic)
        # Starts the threads
        self.client_thread.start()
        self.server_thread.start()
        # Join the threads when done
        self.client_thread.join()
        self.server_thread.join()
        # Release resources
        self.client_sock.close()
        self.server_sock.close()

    @classmethod
    def setup_proxy(cls, proxy_port):
        """ Setup a proxy server """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creating a TCP socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enabling reuse the socket without time limitation
        sock.bind((cls.internal_network, proxy_port))
        sock.listen(10)
        return sock
