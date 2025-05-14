import os
import time
import json
import base64
import socket
import threading
import hashlib
import secrets
from io import BytesIO
from PIL import ImageGrab
from flask import Flask, Response, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO
from cryptography.fernet import Fernet
from pynput.mouse import Button, Controller as MouseController
from screeninfo import get_monitors  # Añade esta importación


# Configuración inicial
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")
mouse = MouseController()

# Configuración de seguridad
AUTH_TOKEN = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
SESSION_TIMEOUT = 1800  # 30 minutos
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Cifrado para transferencia de datos
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)

# Estado del servidor
connected_clients = {}
active_sessions = {}

# Configuración de red
FILE_TRANSFER_PORT = 5001
SCREENSHOT_INTERVAL = 0.2  # 5 FPS
JPEG_QUALITY = 40  # Calidad de imagen (1-100)

def get_local_ips():
    """Obtiene la IP local principal (sin usar netifaces)"""
    ips = []
    try:
        # Esto conecta "falsamente" a una IP pública para descubrir la IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google DNS, no se envía ningún dato
        ip = s.getsockname()[0]
        s.close()
        if ip != "127.0.0.1":
            ips.append(ip)
    except Exception as e:
        print(f"Error obteniendo IP local: {e}")
    return ips or ["127.0.0.1"]

# ------------------------- Ajustar Res ---------------------------
# Agrega esta ruta para obtener la resolución
@app.route('/get_resolution')
def get_resolution():
    monitor = get_monitors()[0]  # Pantalla principal
    return {'width': monitor.width, 'height': monitor.height}

# ------------------------- Autenticación -------------------------
@app.route('/')
def index():
    if 'authenticated' in session and session['authenticated']:
        return redirect(url_for('remote_desktop'))
    return render_template('login.html', token=AUTH_TOKEN)

@app.route('/login', methods=['POST'])
def login():
    token = request.form.get('token')
    if token == AUTH_TOKEN:
        session['authenticated'] = True
        session['ip'] = request.remote_addr
        session['start_time'] = time.time()
        session['session_id'] = secrets.token_hex(16)
        active_sessions[session['session_id']] = {
            'ip': session['ip'],
            'start_time': session['start_time'],
            'last_activity': time.time()
        }
        return redirect(url_for('network_info'))
    return "Token inválido", 403

@app.route('/logout')
def logout():
    if 'session_id' in session:
        active_sessions.pop(session['session_id'], None)
    session.clear()
    return redirect(url_for('index'))

def check_session():
    """Verifica si la sesión es válida"""
    if 'session_id' not in session or session['session_id'] not in active_sessions:
        return False
    if time.time() - active_sessions[session['session_id']]['last_activity'] > SESSION_TIMEOUT:
        return False
    active_sessions[session['session_id']]['last_activity'] = time.time()
    return True

# ------------------------- Captura de Pantalla -------------------------
def capture_screen():
    while True:
        try:
            if not connected_clients:
                time.sleep(1)
                continue

            img = ImageGrab.grab()
            buffer = BytesIO()
            img.save(buffer, format='JPEG', quality=JPEG_QUALITY)
            img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')  # Base64 directo
            
            # Envía SIN cifrar (comenta esta línea si usas Opción 2)
            socketio.emit('screen_update', {'image': img_str})
            
            time.sleep(SCREENSHOT_INTERVAL)
        except Exception as e:
            print(f"Error en captura: {e}")
            time.sleep(5)

# ------------------------- Rutas principales -------------------------
@app.route('/remote')
def remote_desktop():
    if not check_session():
        return redirect(url_for('logout'))
    return render_template('remote.html', max_file_size=MAX_FILE_SIZE)

@app.route('/network_info')
def network_info():
    if not check_session():
        return redirect(url_for('logout'))
    local_ips = get_local_ips()
    return render_template('network_info.html', ips=local_ips)

# ------------------------- WebSockets -------------------------
@socketio.on('connect')
def handle_connect():
    if check_session():
        client_id = request.sid
        connected_clients[client_id] = {
            'ip': request.remote_addr,
            'session_id': session['session_id']
        }
        print(f"Cliente conectado: {client_id}")
        
        # Iniciar captura de pantalla si es el primer cliente
        if len(connected_clients) == 1:
            threading.Thread(target=capture_screen, daemon=True).start()

@socketio.on('disconnect')
def handle_disconnect():
    client_id = request.sid
    if client_id in connected_clients:
        connected_clients.pop(client_id)
        print(f"Cliente desconectado: {client_id}")

# ------------------------- Transferencia de Archivos -------------------------
def handle_file_transfer():
    """Servidor de transferencia de archivos con sockets TCP"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', FILE_TRANSFER_PORT))
        s.listen()
        print(f"Servidor de transferencia de archivos escuchando en puerto {FILE_TRANSFER_PORT}")
        
        while True:
            conn, addr = s.accept()
            try:
                # Autenticación
                auth_token = conn.recv(64).decode('utf-8').strip()
                if auth_token != AUTH_TOKEN:
                    conn.send(b'INVALID_TOKEN')
                    conn.close()
                    continue
                
                # Recibir metadatos
                metadata = json.loads(conn.recv(1024).decode('utf-8'))
                file_name = metadata.get('name', 'archivo')
                file_size = metadata.get('size', 0)
                
                if file_size > MAX_FILE_SIZE:
                    conn.send(b'FILE_TOO_LARGE')
                    conn.close()
                    continue
                
                # Recibir archivo
                received = 0
                file_data = b''
                while received < file_size:
                    data = conn.recv(min(4096, file_size - received))
                    if not data:
                        break
                    file_data += data
                    received += len(data)
                
                # Descifrar y guardar
                decrypted_data = cipher_suite.decrypt(file_data)
                safe_name = ''.join(c for c in file_name if c.isalnum() or c in (' ', '.', '_'))
                save_path = os.path.join('uploads', safe_name)
                
                os.makedirs('uploads', exist_ok=True)
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                
                conn.send(b'FILE_RECEIVED')
                print(f"Archivo recibido: {save_path}")
            except Exception as e:
                print(f"Error en transferencia: {e}")
                conn.send(b'TRANSFER_ERROR')
            finally:
                conn.close()
# ------------------------- Mover Mouse ----------------------------
@socketio.on('mouse_event')
def handle_mouse_event(data):
    try:
        x, y = data['x'], data['y']
        
        # Mapear el número del botón al objeto Button de pynput
        button_map = {
            0: Button.left,   # Clic izquierdo
            1: Button.right,  # Clic derecho
            2: Button.middle  # Clic central
        }
        button = button_map.get(data.get('button', 0), Button.left)  # Default: izquierdo
        
        if data['type'] == 'move':
            mouse.position = (x, y)
        elif data['type'] == 'down':
            mouse.press(button)  # Usar el objeto Button mapeado
        elif data['type'] == 'up':
            mouse.release(button)  # Usar el objeto Button mapeado
    except Exception as e:
        print(f"Error en evento de mouse: {e}")
        
# ------------------------- Inicialización -------------------------
if __name__ == '__main__':
    # Iniciar servidor de transferencia de archivos
    threading.Thread(target=handle_file_transfer, daemon=True).start()
    
    # Mostrar información de conexión
    local_ips = get_local_ips()
    print("\n----- Escritorio Remoto -----")
    print(f"Token de acceso: {AUTH_TOKEN}")
    print("\nConéctate desde otra máquina usando:")
    for ip in local_ips:
        print(f"  http://{ip}:5000")
    print("\nPresiona Ctrl+C para detener el servidor\n")
    
    # Iniciar servidor web
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)