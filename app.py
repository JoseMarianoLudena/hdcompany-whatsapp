from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
import bcrypt
import json
import re
import unicodedata
from openai import OpenAI
import requests
from flask import send_from_directory
import difflib

# Cargar variables de entorno
load_dotenv()
print(f"📢 BASE_URL cargada: {os.getenv('BASE_URL')}")

# Configuración de Flask
app = Flask(__name__, static_folder='images', static_url_path='/images')
app.config['UPLOAD_FOLDER'] = 'images'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')

# Configuración de SocketIO y LoginManager
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuración de WhatsApp
WHATSAPP_PHONE_NUMBER_ID = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
WHATSAPP_ACCESS_TOKEN = os.getenv('WHATSAPP_ACCESS_TOKEN')

# URL base para imágenes (ngrok localmente, Render en producción)
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')

# Configurar OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("Falta OPENAI_API_KEY en .env")

# Cargar datos de HD Company
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
PRODUCTS = json.load(open(os.path.join(DATA_DIR, 'products.json'), 'r', encoding='utf-8'))
FAQS = json.load(open(os.path.join(DATA_DIR, 'faqs.json'), 'r', encoding='utf-8'))
DISCOUNTS = json.load(open(os.path.join(DATA_DIR, 'discounts.json'), 'r', encoding='utf-8'))

# Diccionario para almacenar conversaciones activas
active_conversations = {}

# Clase User para autenticación
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Ruta para servir imágenes
@app.route('/images/<path:filename>')
def serve_image(filename):
    """Sirve imágenes desde la carpeta 'images'."""
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(f"📢 Solicitud de imagen: {full_path}, User-Agent: {request.headers.get('User-Agent')}")
    if os.path.exists(full_path):
        file_size = os.path.getsize(full_path)
        print(f"📢 Sirviendo imagen: {full_path}, tamaño: {file_size} bytes")
        try:
            response = send_from_directory(app.config['UPLOAD_FOLDER'], filename, mimetype='image/png')
            print(f"📢 Imagen enviada con éxito: {full_path}")
            return response
        except Exception as e:
            print(f"❌ Error al servir imagen: {str(e)}")
            return "Error al servir imagen", 500
    else:
        print(f"❌ Imagen no encontrada: {full_path}")
        return "Imagen no encontrada", 404

# Inicializar base de datos
def init_db():
    """Crea las tablas 'clients' y 'users' en la base de datos si no existen."""
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS clients
                     (user_phone TEXT PRIMARY KEY, name TEXT, timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')
        default_username = "admin@hdcompany.com"
        default_password = "HDCompany2025!"
        hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT OR REPLACE INTO users (id, username, password) VALUES ((SELECT id FROM users WHERE username = ?), ?, ?)",
                  (default_username, default_username, hashed_password.decode('utf-8')))
        conn.commit()

init_db()

# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Carga un usuario desde la base de datos para Flask-Login."""
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(id=user_data[0], username=user_data[1])
        return None

# Guardar información del cliente
def save_client(user_phone, name):
    """Guarda o actualiza el nombre y timestamp de un cliente en la base de datos."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO clients (user_phone, name, timestamp) VALUES (?, ?, ?)",
                  (user_phone, name or "Desconocido", timestamp))
        conn.commit()

# Obtener nombre del cliente
def get_client_name(user_phone):
    """Obtiene el nombre de un cliente desde la base de datos."""
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM clients WHERE user_phone = ?", (user_phone,))
        result = c.fetchone()
        return result[0] if result else None

# Obtener todos los clientes
def get_all_clients():
    """Obtiene todos los clientes ordenados por timestamp descendente."""
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT user_phone, name, timestamp FROM clients ORDER BY timestamp DESC")
        return c.fetchall()

# Limpiar conversaciones para el dashboard
def clean_conversations(conversations):
    """Limpia las conversaciones para evitar errores de serialización JSON."""
    cleaned = {}
    for user_phone, data in conversations.items():
        messages = []
        for msg in data.get("messages", []):
            message = msg.get("message", "")
            sender = msg.get("sender", "unknown")
            timestamp = msg.get("timestamp", "")
            if message is None:
                message = ""
            if sender is None:
                sender = "unknown"
            if timestamp is None:
                timestamp = ""
            messages.append({
                "message": str(message).replace('"', '\\"').replace('\n', '\\n'),
                "sender": str(sender),
                "timestamp": str(timestamp)
            })
        cleaned[user_phone] = {
            "messages": messages,
            "escalated": bool(data.get("escalated", False)),
            "state": str(data.get("state", "initial")),
            "name": str(data.get("name", "Desconocido")) if data.get("name") else "Desconocido",
            "last_product": data.get("last_product", {})
        }
    return cleaned

# Enviar mensaje por WhatsApp
def send_whatsapp_message(to_phone, message=None, image_url=None, buttons=None, list_menu=None):
    """Envía un mensaje por WhatsApp, con soporte para texto, imágenes, botones y menús interactivos."""
    endpoint = f"https://graph.facebook.com/v20.0/{os.getenv('WHATSAPP_PHONE_NUMBER_ID')}/messages"
    headers = {
        "Authorization": f"Bearer {os.getenv('WHATSAPP_ACCESS_TOKEN')}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone.replace("whatsapp:", ""),
    }

    if image_url:
        # Verificar si la imagen existe en el servidor
        file_name = image_url.split('/')[-1]
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        print(f"📢 Verificando archivo en: {full_path}")
        if os.path.exists(full_path):
            # Enviar la imagen
            image_payload = {
                "messaging_product": "whatsapp",
                "to": to_phone.replace("whatsapp:", ""),
                "type": "image",
                "image": {
                    "link": image_url
                }
            }
            print(f"📢 Enviando imagen: {json.dumps(image_payload, ensure_ascii=False)}")
            image_response = requests.post(endpoint, headers=headers, json=image_payload)
            print(f"📢 Respuesta de WhatsApp API (imagen): {image_response.status_code} {image_response.text}")
            if image_response.status_code == 200:
                # Enviar mensaje de texto con lista de opciones
                text_payload = {
                    "messaging_product": "whatsapp",
                    "to": to_phone.replace("whatsapp:", ""),
                    "type": "interactive",
                    "interactive": {
                        "type": "list",
                        "body": {"text": message},
                        "action": {
                            "button": "Ver Opciones",
                            "sections": [
                                {
                                    "title": "Opciones del Producto",
                                    "rows": [
                                        {"id": "add_to_cart", "title": "Agregar al Carrito"},
                                        {"id": "view_image", "title": "Ver Imagen"},
                                        {"id": "view_specs", "title": "Ver Especificaciones"},
                                        {"id": "return_menu", "title": "Regresar al Menú"}
                                    ]
                                }
                            ]
                        }
                    }
                }
                text_response = requests.post(endpoint, headers=headers, json=text_payload)
                print(f"📢 Respuesta de WhatsApp API (texto con lista): {text_response.status_code} {text_response.text}")
                if text_response.status_code == 200:
                    return {"status": "success", "message_id": text_response.json().get("messages", [{}])[0].get("id", "")}
                else:
                    print(f"❌ Error al enviar mensaje de texto: {text_response.text}")
                    return {"status": "error", "error": "No se pudo enviar el mensaje de texto"}
            else:
                print(f"❌ Error al enviar imagen: {image_response.text}")
                payload["type"] = "text"
                payload["text"] = {"body": f"Lo siento, no pude enviar la imagen. 😅 Visita https://mitienda.today/hdcompany para verlo."}
                response = requests.post(endpoint, json=payload, headers=headers)
                print(f"📢 Respuesta de WhatsApp API: {response.status_code} {response.text}")
                return {"status": "error", "error": "No se pudo enviar la imagen"}
        else:
            print(f"❌ Archivo no encontrado en el servidor: {full_path}")
            payload["type"] = "text"
            payload["text"] = {"body": f"Lo siento, la imagen no está disponible. 😅 Visita https://mitienda.today/hdcompany para verlo."}
            response = requests.post(endpoint, json=payload, headers=headers)
            print(f"📢 Respuesta de WhatsApp API: {response.status_code} {response.text}")
            return {"status": "error", "error": "Archivo no encontrado"}
    elif list_menu:
        payload["type"] = "interactive"
        payload["interactive"] = {
            "type": "list",
            "body": {"text": message},
            "action": {
                "button": "Ver Opciones",
                "sections": [
                    {
                        "title": "Menú Principal",
                        "rows": list_menu
                    }
                ]
            }
        }
    elif buttons:
        payload["type"] = "interactive"
        payload["interactive"] = {
            "type": "button",
            "body": {"text": message},
            "action": {
                "buttons": [
                    {"type": "reply", "reply": {"id": btn["id"], "title": btn["title"]}} for btn in buttons
                ]
            }
        }
    else:
        payload["type"] = "text"
        payload["text"] = {"body": message}
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        print(f"📢 Respuesta de WhatsApp API: {response.status_code} {response.text}")
        if response.status_code == 200:
            message_id = response.json().get("messages", [{}])[0].get("id", "Unknown")
            print(f"📢 Mensaje enviado a {to_phone}: ID {message_id}")
            return {"status": "success", "message_id": message_id}
        else:
            print(f"❌ Error al enviar mensaje: {response.status_code} {response.text}")
            return {"status": "error", "error": response.text}
    except Exception as e:
        print(f"❌ Excepción al enviar mensaje: {str(e)}")
        return {"status": "error", "error": str(e)}

# Ruta para login
@app.route("/login", methods=["GET", "POST"])
def login():
    """Maneja el inicio de sesión de agentes."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        with sqlite3.connect("clients.db") as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            user_data = c.fetchone()
            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
                user = User(id=user_data[0], username=user_data[1])
                login_user(user)
                return redirect(url_for('dashboard'))
            flash("Credenciales inválidas. Inténtalo de nuevo.", "error")
    return render_template("login.html")

# Ruta para logout
@app.route("/logout")
@login_required
def logout():
    """Cierra la sesión del agente."""
    logout_user()
    return redirect(url_for('login'))

# Procesar mensajes de WhatsApp
@app.route("/process", methods=["POST"])
def process_message():
    """Procesa los mensajes recibidos desde Make.com."""
    print(f"📢 Headers recibidos: {request.headers}")
    print(f"📢 Raw body recibido: {request.get_data(as_text=True)}")
    webhook_token = request.headers.get("X-Webhook-Token") or request.args.get("hub.verify_token")
    if webhook_token and webhook_token != os.getenv("WHATSAPP_WEBHOOK_TOKEN"):
        print(f"❌ Token de webhook inválido: {webhook_token}")
        return jsonify({"error": "Invalid webhook token"}), 403

    try:
        data = request.json
        print(f"📢 JSON completo recibido desde Make.com: {json.dumps(data, ensure_ascii=False)}")
        user_phone = data.get("from", "")
        user_input = data.get("text", "")

        if not user_input and data.get("messages"):
            for message in data.get("messages", []):
                if message.get("type") == "interactive":
                    interactive = message.get("interactive", {})
                    if interactive.get("type") == "button_reply":
                        user_input = interactive["button_reply"]["id"]
                        break
                    elif interactive.get("type") == "list_reply":
                        user_input = interactive["list_reply"]["id"]
                        break

        if not user_input or not user_phone:
            print(f"❌ Error: Faltan text o from en el JSON: {data}")
            return jsonify({"error": "Faltan text o from"}), 400

        print(f"📢 Procesando mensaje de {user_phone}: {user_input}")
        response = handle_user_input(user_input, user_phone)
        print(f"📢 Enviando respuesta a Make.com: {response}")
        return jsonify(response), 200
    except Exception as e:
        print(f"❌ Error en /process: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Dashboard para agentes
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    """Muestra el dashboard para agentes y permite enviar mensajes manuales."""
    print(f"📢 active_conversations: {active_conversations}")
    if request.method == "POST":
        user_phone = request.form.get("user_phone")
        message = request.form.get("message")
        if user_phone and message:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if user_phone not in active_conversations:
                active_conversations[user_phone] = {
                    "messages": [],
                    "escalated": False,
                    "state": "initial",
                    "name": get_client_name(user_phone),
                    "last_product": {},
                    "last_category": None,
                    "cart": []
                }
            active_conversations[user_phone]["messages"].append({"message": message, "sender": "agent", "timestamp": timestamp})
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message)
            print(f"📢 Mensaje enviado a whatsapp:{user_phone}: {message}")
            socketio.emit('new_message', {
                'user_phone': user_phone,
                'message': message,
                'sender': 'agent',
                'timestamp': timestamp,
                'name': active_conversations[user_phone]["name"],
                'escalated': active_conversations[user_phone]["escalated"],
                'state': active_conversations[user_phone]["state"]
            }, namespace='/dashboard')
            return render_template("dashboard.html", conversations=clean_conversations(active_conversations), success="Mensaje enviado correctamente", current_user=current_user)
        return render_template("dashboard.html", conversations=clean_conversations(active_conversations), error="Faltan datos", current_user=current_user)
    return render_template("dashboard.html", conversations=clean_conversations(active_conversations), current_user=current_user)

# Lista de clientes
@app.route("/clients", methods=["GET"])
@login_required
def clients():
    """Muestra la lista de clientes en el dashboard."""
    clients = get_all_clients()
    return render_template("clients.html", clients=clients, current_user=current_user)

# Manejar conexión de SocketIO
@socketio.on('connect', namespace='/dashboard')
def handle_connect():
    """Maneja la conexión de un cliente al dashboard."""
    print("📢 Cliente conectado al dashboard")
    emit('update_conversations', clean_conversations(active_conversations), namespace='/dashboard')

# Normalizar texto
def normalize_text(text):
    """Normaliza el texto eliminando acentos y convirtiendo a minúsculas."""
    text = ''.join(c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn')
    return text.lower().strip()

# Encontrar producto en la respuesta de OpenAI
def find_product_in_response(response_text, products, user_input):
    """Busca un producto en la respuesta de OpenAI usando coincidencias exactas, prefijos o cercanas."""
    normalized_response = normalize_text(response_text)
    normalized_input = normalize_text(user_input)

    # Identificar la categoría implícita en la pregunta del usuario
    category_keywords = {
        "tablet": "Tablets y Celulares",
        "celular": "Tablets y Celulares",
        "laptop": "Laptops y Accesorios",
        "computadora": "Laptops y Accesorios",
        "mouse": "Mouse y Teclado",
        "teclado": "Mouse y Teclado",
        "monitor": "Monitores y TV",
        "case": "Case y Accesorios",
        "camara": "Cámaras Web y Vigilancia",
        "disco": "Discos Duros y Sólidos",
        "impresora": "Impresoras y Accesorios",
        "tarjeta": "Tarjetas de Video",
        "oferta": "OFERTAS"
    }
    target_category = None
    for keyword, category in category_keywords.items():
        if keyword in normalized_input:
            target_category = category
            break

    # Filtrar productos por categoría
    filtered_products = products
    if target_category:
        if target_category == "Laptops y Accesorios":
            filtered_products = [p for p in products if p['categoria'] == target_category and "Laptop" in p['nombre']]
        elif target_category == "Impresoras y Accesorios":
            filtered_products = [p for p in products if p['categoria'] == target_category and "Impresora" in p['nombre']]
        else:
            filtered_products = [p for p in products if p['categoria'] == target_category]
        print(f"📢 Filtrando productos por categoría: {target_category}")

    # Extraer el nombre del producto entre corchetes
    response_product_name = None
    match = re.search(r'\[(.*?)\]', normalized_response)
    if match:
        response_product_name = match.group(1)
        print(f"📢 Nombre de producto extraído entre corchetes: {response_product_name}")

    # Buscar el producto en filtered_products
    if response_product_name:
        normalized_response_product = normalize_text(response_product_name)
        for product in filtered_products:
            normalized_product_name = normalize_text(product['nombre'])
            # Comparar si el nombre extraído es un prefijo del nombre completo
            if normalized_response_product in normalized_product_name:
                print(f"📢 Producto encontrado (prefijo): {product['nombre']} en respuesta: {response_text}")
                return product
            # Comparar nombre inicial (hasta la primera coma o más específico para laptops)
            short_product_name = normalize_text(product['nombre'].split(',')[0].strip())
            if "laptop" in normalized_input:
                # Para laptops, incluir más detalles del nombre inicial (hasta el modelo)
                short_product_name = normalize_text(' '.join(product['nombre'].split()[:5]))  # Ej. "Laptop HP ProBook 450 G9"
            if normalized_response_product == short_product_name:
                print(f"📢 Producto encontrado (coincidencia en nombre inicial): {product['nombre']} en respuesta: {response_text}")
                return product
            # Usar difflib para coincidencias cercanas (menos prioridad)
            cutoff = 0.8 if "laptop" in normalized_input else 0.6
            matches = difflib.get_close_matches(normalized_response_product, [normalized_product_name, short_product_name], n=1, cutoff=cutoff)
            print(f"📢 Coincidencias cercanas para '{response_product_name}' con cutoff={cutoff}: {matches}")
            if matches and (matches[0] == normalized_product_name or matches[0] == short_product_name):
                print(f"📢 Producto encontrado (coincidencia cercana): {product['nombre']} en respuesta: {response_text}")
                return product

    # Respaldo: si no se encuentra, crear un producto temporal
    if response_product_name and target_category:
        # Buscar una imagen de la misma categoría como respaldo
        image_url = None
        for product in filtered_products:
            if product.get('image_url'):
                image_url = product['image_url'].lstrip('/')
                break
        print(f"📢 Producto no encontrado en JSON, creando respaldo: {response_product_name}")
        return {
            "nombre": response_product_name,
            "categoria": target_category,
            "image_url": image_url if image_url else None,
            "descripcion": "Especificaciones no disponibles en el catálogo. Consulta en https://mitienda.today/hdcompany.",
            "precio": re.search(r'PEN \d+\.\d{2}', response_text).group(0) if re.search(r'PEN \d+\.\d{2}', response_text) else "PEN 0.00"
        }

    print(f"📢 No se encontró producto en respuesta: {response_text}")
    return None

# Encontrar producto por nombre o posición
def find_product_by_name_or_position(user_input, products, last_category=None):
    """Busca un producto por nombre o posición (primero, segundo, tercero) en una categoría."""
    normalized_input = normalize_text(user_input)
    
    position_keywords = {
        "primero": 0, "primer": 0, "1": 0,
        "segundo": 1, "2": 1,
        "tercero": 2, "3": 2
    }
    if last_category:
        filtered_products = [p for p in products if p['categoria'] == last_category]
        if last_category == "Laptops y Accesorios":
            filtered_products = [p for p in filtered_products if "Laptop" in p['nombre']]
        elif last_category == "Impresoras y Accesorios":
            filtered_products = [p for p in filtered_products if "Impresora" in p['nombre']]
        for keyword, index in position_keywords.items():
            if keyword in normalized_input:
                if index < len(filtered_products):
                    return filtered_products[index]
                return None

    for product in products:
        normalized_product_name = normalize_text(product['nombre'])
        if normalized_input in normalized_product_name or normalized_product_name in normalized_input:
            return product
    return None

# Manejar entrada del usuario
def handle_user_input(user_input, user_phone):
    """Procesa la entrada del usuario y genera la respuesta adecuada."""
    # Definir palabras clave
    close_keywords = ["gracias", "resuelto", "listo", "ok", "solucionado"]
    escalation_keywords = ["agente", "humano", "persona", "hablar con alguien"]
    greeting_keywords = ["hola", "que tal", "buenos dias", "buenas tardes", "buenas noches", "hey", "saludos"]
    availability_keywords = ["tienes", "hay", "dispones", "existen"]
    more_info_keywords = ["mas informacion", "mas detalles", "si", "mas info", "detalles", "more_info"]

    # Definir menús y botones
    menu_list = [
        {"id": "offers", "title": "Ofertas"},
        {"id": "laptops", "title": "Laptops"},
        {"id": "printers", "title": "Impresoras"},
        {"id": "accessories", "title": "Accesorios y Otros"},
        {"id": "support", "title": "Agendar Soporte Técnico"},
        {"id": "agent", "title": "Hablar con Agente"}
    ]

    product_buttons = [
        {"id": "view_image", "title": "Ver Imagen"},
        {"id": "view_specs", "title": "Ver Especificaciones"},
        {"id": "return_menu", "title": "Regresar al Menú"}
    ]

    recommendation_options = [
        {"id": "add_to_cart", "title": "Agregar al Carrito"},
        {"id": "view_image", "title": "Ver Imagen"},
        {"id": "view_specs", "title": "Ver Especificaciones"},
        {"id": "return_menu", "title": "Regresar al Menú"}
    ]

    return_menu_button = [
        {"id": "return_menu", "title": "Regresar al Menú"}
    ]

    cart_buttons = [
        {"id": "buy_now", "title": "Comprar Ahora"},
        {"id": "keep_browsing", "title": "Seguir Viendo"},
        {"id": "view_cart_images", "title": "Ver Imágenes Carrito"}
    ]

    accessory_categories = [
        {"id": "category_case", "title": "Case y Accesorios"},
        {"id": "category_cameras", "title": "Cámaras Web y Vigilancia"},
        {"id": "category_disks", "title": "Discos Duros y Sólidos"},
        {"id": "category_monitors", "title": "Monitores y TV"},
        {"id": "category_mouse_keyboard", "title": "Mouse y Teclado"},
        {"id": "category_video_cards", "title": "Tarjetas de Video"},
        {"id": "category_tablets", "title": "Tablets y Celulares"},
        {"id": "return_menu", "title": "Regresar al Menú"}
    ]

    # Inicializar conversación si no existe
    if user_phone not in active_conversations:
        print(f"📢 Inicializando nueva conversación para {user_phone}")
        active_conversations[user_phone] = {
            "messages": [],
            "escalated": False,
            "state": "initial",
            "name": get_client_name(user_phone),
            "last_product": {},
            "last_category": None,
            "last_product_list": [],  # Nuevo campo para almacenar la última lista de productos
            "cart": []
        }

    # Registrar mensaje del usuario
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    display_message = user_input
    if any(keyword in user_input.lower() for keyword in escalation_keywords) or user_input == "agent":
        display_message = "El usuario quiere hablar con un agente"

    active_conversations[user_phone]["messages"].append({"message": display_message, "sender": "client", "timestamp": timestamp})

    socketio.emit('new_message', {
        'user_phone': user_phone,
        'message': display_message,
        'sender': 'client',
        'timestamp': timestamp,
        'name': active_conversations[user_phone]["name"],
        'escalated': active_conversations[user_phone]["escalated"],
        'state': active_conversations[user_phone]["state"]
    }, namespace='/dashboard')

    # Manejar cierre de conversación
    if any(keyword in user_input.lower() for keyword in close_keywords):
        print(f"📢 Cerrando conversación para {user_phone}")
        response = "¡Gracias por contactarnos! 😊 Escríbenos si necesitas más ayuda."
        del active_conversations[user_phone]
        socketio.emit('close_conversation', {'user_phone': user_phone}, namespace='/dashboard')
        return {"response": response}

    # Ignorar mensajes si la conversación está escalada
    if active_conversations[user_phone]["escalated"]:
        print(f"📢 Conversación escalada para {user_phone}, ignorando mensaje")
        return {"response": ""}

    # Manejar solicitud de agente
    if any(keyword in user_input.lower() for keyword in escalation_keywords) or user_input == "agent":
        print(f"📢 Escalando conversación para {user_phone}")
        active_conversations[user_phone]["escalated"] = True
        send_whatsapp_message(os.getenv("AGENT_PHONE_NUMBER", "whatsapp:+51992436107"), f"🔔 Nueva solicitud de agente humano!\nUsuario: {user_phone}\nMensaje: {user_input}")
        return {"response": "🔔 Te conecto con un agente. ¡Un momento! 😊"}

    normalized_input = normalize_text(user_input)
    print(f"📢 Input normalizado: {normalized_input}, estado: {active_conversations[user_phone]['state']}")

    # Mapear "Agregar al Carrito" a "add_to_cart"
    if normalized_input == "agregar al carrito":
        user_input = "add_to_cart"

    # Manejar estado awaiting_cart_action
    if active_conversations[user_phone]["state"] == "awaiting_cart_action":
        if user_input == "buy_now":
            message = (
                "🛒 ¡Gracias por tu pedido!\n"
                "💳 Puedes hacer el pago al siguiente YAPE o PLIN: 📱 +51 957 670 299\n"
                "Una vez que realices el pago, por favor envíanos una captura del comprobante para preparar tu pedido✅\n"
                "📦 Si prefieres pagar en persona o ver los productos directamente, también puedes visitarnos en tienda. ¡Te esperamos!"
            )
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
            active_conversations[user_phone]["state"] = "awaiting_query"
            active_conversations[user_phone]["cart"] = []
            return {"response": message, "sent_by_app": True}
        elif user_input == "keep_browsing":
            message = f"¡Perfecto! 😊 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            active_conversations[user_phone]["state"] = "awaiting_query"
            return {"response": message, "sent_by_app": True}
        elif user_input == "view_cart_images":
            cart_items = active_conversations[user_phone]["cart"]
            if cart_items:
                message = f"📷 Imágenes de los productos en tu carrito:\n"
                for item in cart_items:
                    image_path = item.get('image_url', '').lstrip('/') if item.get("image_url") else None
                    image_url = f"{BASE_URL}/{image_path}" if image_path else None
                    if image_url:
                        message += f"- {item['nombre']}\n"
                        send_whatsapp_message(f"whatsapp:{user_phone}", f"📷 {item['nombre']}", image_url=image_url)
                    else:
                        message += f"- {item['nombre']} (sin imagen disponible)\n"
                message += f"¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 Tu carrito está vacío. Selecciona un producto primero."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
        elif re.search(r'\b(ver|mirar|mostrar|quiero ver|carrito)\b', normalized_input) and "carrito" in normalized_input:
            cart_items = active_conversations[user_phone]["cart"]
            if cart_items:
                total_price = sum(float(item['precio'].replace('PEN ', '')) for item in cart_items)
                cart_list = "\n".join([f"🛍️ {item['nombre']} - Precio: {item['precio']}" for item in cart_items])
                message = (
                    f"🛒 Productos del Carrito:\n"
                    f"{cart_list}\n"
                    f"💵 Total a Pagar: PEN {total_price:.2f}\n"
                    f"{'-' * 55}\n"
                    f"¿Qué deseas hacer, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                )
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 Tu carrito está vacío. Selecciona un producto primero."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
        else:
            message = f"Por favor, selecciona una opción válida: Comprar Ahora, Seguir Viendo o Ver Imágenes Carrito."
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
            return {"response": message, "sent_by_app": True}

    # Manejar estado awaiting_menu_confirmation
    if active_conversations[user_phone]["state"] == "awaiting_menu_confirmation":
        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Perfecto! 😊 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        # Manejar solicitud de "quiero una impresora"
        if re.search(r'\b(quiero|necesito|busco)\b.*\bimpresora\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and p['nombre'].startswith("Impresora")]
            if products_in_category:
                recommended_product = products_in_category[0]  # Recomendar la primera impresora
                active_conversations[user_phone]["last_product"] = recommended_product
                active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                message = f"Te recomiendo {recommended_product['nombre']} por {recommended_product['precio']} [{recommended_product['nombre']}]. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no tenemos impresoras disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de "impresoras térmicas" o "multifuncionales"
        if re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\bimpresoras?\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and p['nombre'].startswith("Impresora")]
            if re.search(r'\bt[eé]rmicas?\b', normalized_input):
                products_in_category = [p for p in products_in_category if "Térmica" in p['nombre']]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos impresoras térmicas! 😄\nProductos en Impresoras Térmicas:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos impresoras térmicas disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
            elif re.search(r'\bmultifuncional(es)?\b', normalized_input):
                products_in_category = [p for p in products_in_category if "Multifuncional" in p['nombre'] or all(keyword in p['descripcion'].lower() for keyword in ["imprime", "escanea", "copia"])]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos impresoras multifuncionales! 😄\nProductos en Impresoras Multifuncionales:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos impresoras multifuncionales disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
            else:
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos impresoras! 😄\nProductos en Impresoras:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos impresoras disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}

        # Manejar solicitud de laptops
        if re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\b(laptop|computadora)\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and p['nombre'].startswith("Laptop")]
            if re.search(r'\b(hp|lenovo|asus|dell|acer)\b', normalized_input):
                brand = re.search(r'\b(hp|lenovo|asus|dell|acer)\b', normalized_input).group(0).upper()
                products_in_category = [p for p in products_in_category if brand in p['nombre'].upper()]
                category_label = f"Laptops {brand}"
            elif re.search(r'\b(gamer|gaming)\b', normalized_input):
                products_in_category = [p for p in products_in_category if "Gamer" in p['nombre'] or any(spec in p['descripcion'].lower() for spec in ["ryzen 7", "core i7", "16gb", "rtx", "gtx"])]
                category_label = "Laptops Gamer"
            else:
                category_label = "Laptops"
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"¡Sí, tenemos {category_label.lower()}! 😄\nProductos en {category_label}:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no tenemos {category_label.lower()} disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de tablets
        if re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\b(tablets?|tabletas?)\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Tablets y Celulares" and "Tablet" in p['nombre']]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"¡Sí, tenemos tablets! 😄\nProductos en Tablets:\n{product_list}\nSelecciona una tablet o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Tablets y Celulares"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no tenemos tablets disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de accesorios
        if re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\b(accesorios|mouse|teclado|cámara|webcam|disco|monitor|tarjeta de video)\b', normalized_input):
            accessory_categories = ["Mouse y Teclado", "Cámaras Web y Vigilancia", "Discos Duros y Sólidos", "Monitores y TV", "Tarjetas de Video"]
            selected_category = None
            for cat in accessory_categories:
                if normalize_text(cat).lower() in normalized_input:
                    selected_category = cat
                    break
            if selected_category:
                products_in_category = [p for p in PRODUCTS if p['categoria'] == selected_category]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos {category_short_names.get(selected_category, selected_category).lower()}! 😄\nProductos en {category_short_names.get(selected_category, selected_category)}:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = selected_category
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos {category_short_names.get(selected_category, selected_category).lower()} disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
            else:
                message = f"Por favor, especifica qué tipo de accesorios buscas (ej. mouse, teclado, webcam). 😄 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=accessory_categories)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud explícita de más impresoras
        if re.search(r'\b(muestrame|quiero|ver)\s*(mas|más)\s*(impresoras|impresora|t[eé]rmicas|t[eé]rmica)\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and p['nombre'].startswith("Impresora")]
            if re.search(r'\bt[eé]rmicas?\b', normalized_input):
                products_in_category = [p for p in products_in_category if "Térmica" in p['nombre']]
                category_label = "Impresoras Térmicas"
            else:
                category_label = "Impresoras"
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en {category_label}:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no tenemos más {category_label.lower()} disponibles. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud explícita de más laptops
        if re.search(r'\b(muestrame|quiero|ver)\s*(mas|más)\s*(laptops|laptop|computadoras)\b', normalized_input):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and p['nombre'].startswith("Laptop")]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Laptops:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no tenemos más laptops disponibles. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud genérica de "más productos de este tipo"
        if re.search(r'\b(muestrame|quiero|ver)\s*(mas|más)\s*(productos|de este tipo|de estos)\b', normalized_input):
            last_product = active_conversations[user_phone].get('last_product')
            if last_product:
                category = last_product.get('categoria')
                if category:
                    products_in_category = [p for p in PRODUCTS if p['categoria'] == category]
                    if category == "Laptops y Accesorios":
                        products_in_category = [p for p in products_in_category if p['nombre'].startswith("Laptop")]
                    elif category == "Impresoras y Accesorios":
                        products_in_category = [p for p in products_in_category if p['nombre'].startswith("Impresora")]
                    if products_in_category:
                        product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                        message = f"Productos en {category_short_names.get(category, category)}:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        active_conversations[user_phone]["last_category"] = category
                        active_conversations[user_phone]["last_product_list"] = products_in_category
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                        active_conversations[user_phone]["state"] = "awaiting_query"
                        return {"response": message, "sent_by_app": True}
                    else:
                        message = f"Lo siento, no tenemos más {category_short_names.get(category, category)} disponibles. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                        active_conversations[user_phone]["state"] = "awaiting_query"
                        return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no sé a qué categoría te refieres. 😅 ¿Quieres ver laptops, impresoras u otra cosa?"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no sé a qué categoría te refieres. 😅 ¿Quieres ver laptops, impresoras u otra cosa?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de imagen
        if re.search(r'\b(imagen|foto|ver.*producto|como.*es|puedo.*ver)\b', normalized_input) or user_input == "view_image":
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                image_path = product.get('image_url', '').lstrip('/') if product.get("image_url") else None
                image_url = f"{BASE_URL}/{image_path}" if image_path else None
                print(f"📢 Intentando enviar imagen: {image_url}")
                if image_url:
                    message = f"📷 Imagen de {product['nombre']}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url, buttons=recommendation_options)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
                else:
                    print(f"❌ Imagen no encontrada: {image_url}")
                    message = f"Lo siento, no tengo imagen de {product['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de especificaciones
        if any(keyword in normalized_input for keyword in more_info_keywords) or user_input == "view_specs":
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                message = f"🛍️ {product['nombre']}: {product['descripcion']}. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        # Manejar agregar al carrito
        if user_input == "add_to_cart":
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                active_conversations[user_phone]["cart"].append(product)
                cart_items = active_conversations[user_phone]["cart"]
                if cart_items:
                    total_price = sum(float(item['precio'].replace('PEN ', '')) for item in cart_items)
                    cart_list = "\n".join([f"🛍️ {item['nombre']} - Precio: {item['precio']}" for item in cart_items])
                    message = (
                        f"🛒 Productos del Carrito:\n"
                        f"{cart_list}\n"
                        f"💵 Total a Pagar: PEN {total_price:.2f}\n"
                        f"{'-' * 55}\n"
                        f"¿Qué deseas hacer, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    )
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_cart_action"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"😔 Tu carrito está vacío. Selecciona un producto primero."
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        # Consulta a OpenAI para clasificar la intención
        try:
            recent_messages = active_conversations[user_phone]["messages"][-3:]
            context = "\n".join([f"{msg['sender']}: {msg['message']}" for msg in recent_messages])
            last_product = active_conversations[user_phone].get('last_product', {}).get('nombre', 'ninguno')
            last_category = active_conversations[user_phone].get('last_category', 'ninguna')
            categories = list(set(p['categoria'] for p in PRODUCTS))
            category_short_names = {
                "Laptops y Accesorios": "Laptops",
                "Impresoras y Accesorios": "Impresoras",
                "Case y Accesorios": "Cases",
                "Cámaras Web y Vigilancia": "Cámaras Web",
                "Discos Duros y Sólidos": "Discos Duros",
                "Monitores y TV": "Monitores",
                "Mouse y Teclado": "Mouse y Teclado",
                "Tarjetas de Video": "Tarjetas de Video",
                "Tablets y Celulares": "Tablets",
                "OFERTAS": "Ofertas"
            }
            category_menu = [{"id": f"category_{normalize_text(cat)}", "title": category_short_names.get(cat, cat)[:24]} for cat in categories]

            prompt = (
                f"Eres un asistente de HD Company, tienda de tecnología en Lima, Perú.\n"
                f"Contexto: {context}\n"
                f"Información:\n"
                f"- Categorías: {json.dumps(categories, ensure_ascii=False)}.\n"
                f"- Último producto: {last_product}.\n"
                f"- Última categoría: {last_category}.\n"
                f"Clasifica la intención del usuario para '{user_input}' en JSON con:\n"
                f"- intent: ['list_products', 'select_category', 'recommend_product', 'product_function', 'view_cart']\n"
                f"- category: Categoría relevante (ej. 'Laptops y Accesorios' para laptops, 'Impresoras y Accesorios' para impresoras) o null. Para frases como 'más productos de este tipo', usa la categoría del último producto recomendado ({last_product}).\n"
                f"- product: Nombre del producto (ej. 'Impresora Multifuncional de Tinta EPSON L3250') o null\n"
                f"- response: Respuesta en español, amigable, máx. 300 caracteres, sin generar listas ni productos\n"
                f"Reglas:\n"
                f"- 'list_products': Si pide lista (ej. 'muéstrame más impresoras', 'quiero más laptops', 'más productos de este tipo'). Usa 'Impresoras y Accesorios' para impresoras, 'Laptops y Accesorios' para laptops, o la categoría del último producto para 'más de este tipo'.\n"
                f"- 'select_category': Si pide explorar categorías (ej. 'quiero algo diferente').\n"
                f"- 'recommend_product': Si pide recomendación específica (ej. 'qué impresora me recomiendas').\n"
                f"- 'product_function': Si pregunta cómo funciona un producto (ej. 'cómo funciona la impresora EPSON').\n"
                f"- 'view_cart': Si pide ver el carrito (ej. 'quiero ver el carrito', 'qué productos tiene el carrito').\n"
                f"- No generar listas de productos; el código maneja listas desde products.json.\n"
                f"- Si no hay más productos, di: 'Lo siento, no tenemos más [category] disponibles.'\n"
                f"- Para 'product_function', simula búsqueda en internet si el producto no está en la lista (máx. 100 palabras).\n"
                f"- Termina con: '¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄'\n"
                f"Return only the JSON."
            )
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150
            )
            try:
                ai_response = json.loads(response.choices[0].message.content.strip()) if response.choices else {
                    "intent": "select_category",
                    "category": None,
                    "product": None,
                    "response": f"Lo siento, no entendí. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                }
            except json.JSONDecodeError as e:
                print(f"❌ Error parseando JSON de OpenAI: {str(e)}")
                ai_response = {
                    "intent": "select_category",
                    "category": None,
                    "product": None,
                    "response": f"Lo siento, no entendí. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                }
            intent = ai_response.get("intent")
            category = ai_response.get("category")
            product_name = ai_response.get("product")
            message = ai_response.get("response", f"Lo siento, no entendí. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄")

            # Procesar según la intención
            if intent == "view_cart":
                cart_items = active_conversations[user_phone]["cart"]
                if cart_items:
                    total_price = sum(float(item['precio'].replace('PEN ', '')) for item in cart_items)
                    cart_list = "\n".join([f"🛍️ {item['nombre']} - Precio: {item['precio']}" for item in cart_items])
                    message = (
                        f"🛒 Productos del Carrito:\n"
                        f"{cart_list}\n"
                        f"💵 Total a Pagar: PEN {total_price:.2f}\n"
                        f"{'-' * 55}\n"
                        f"¿Qué deseas hacer, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    )
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_cart_action"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"😔 Tu carrito está vacío. Selecciona un producto primero."
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}

            if intent == "list_products" and category:
                products_in_category = [p for p in PRODUCTS if p['categoria'] == category]
                if category == "Laptops y Accesorios":
                    products_in_category = [p for p in products_in_category if p['nombre'].startswith("Laptop")]
                elif category == "Impresoras y Accesorios":
                    products_in_category = [p for p in products_in_category if p['nombre'].startswith("Impresora")]
                    if re.search(r'\bt[eé]rmicas?\b', normalized_input):
                        products_in_category = [p for p in products_in_category if "Térmica" in p['nombre']]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"Productos en {category_short_names.get(category, category)}{' Térmicas' if 'termica' in normalized_input or 'térmica' in normalized_input else ''}:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = category
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos más {category_short_names.get(category, category)}{' térmicas' if 'termica' in normalized_input or 'térmica' in normalized_input else ''} disponibles. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}

            elif intent == "select_category":
                message = f"📋 Elige una categoría para explorar productos:"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=category_menu)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

            elif intent == "recommend_product" and category:
                products_in_category = [p for p in PRODUCTS if p['categoria'] == category and p['nombre'] != last_product]
                if category == "Laptops y Accesorios":
                    products_in_category = [p for p in products_in_category if p['nombre'].startswith("Laptop")]
                    if "gamer" in normalized_input:
                        products_in_category = [p for p in products_in_category if any(spec in p['descripcion'].lower() for spec in ["ryzen 7", "core i7", "16gb"])]
                elif category == "Impresoras y Accesorios":
                    products_in_category = [p for p in products_in_category if p['nombre'].startswith("Impresora")]
                    if re.search(r'\bt[eé]rmicas?\b', normalized_input):
                        products_in_category = [p for p in products_in_category if "Térmica" in p['nombre']]
                if products_in_category:
                    recommended_product = products_in_category[0]
                    active_conversations[user_phone]["last_product"] = recommended_product
                    active_conversations[user_phone]["last_category"] = category
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    message = f"Te recomiendo {recommended_product['nombre']} por {recommended_product['precio']} [{recommended_product['nombre']}]. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos más {category_short_names.get(category, category)}{' térmicas' if 'termica' in normalized_input or 'térmica' in normalized_input else ''} disponibles. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    return {"response": message, "sent_by_app": True}

            elif intent == "product_function" and product_name:
                product = next((p for p in PRODUCTS if p['nombre'].lower() == product_name.lower()), None)
                if product:
                    message = f"{product['nombre']}: {product['descripcion']}. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
                else:
                    function_prompt = (
                        f"Busca cómo funciona '{product_name}' y resume en 2-3 frases (máx. 100 palabras). "
                        f"Responde en español, amigable. Ejemplo: 'La Impresora EPSON L3250 imprime, escanea y copia con conexión WiFi.' "
                        f"Termina con: '¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄'"
                    )
                    function_response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": function_prompt}],
                        max_tokens=100
                    )
                    message = function_response.choices[0].message.content if function_response.choices else f"No encontré detalles sobre {product_name}. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}

            else:
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            active_conversations[user_phone]["state"] = "awaiting_query"
            return {"response": message, "sent_by_app": True}

    # Manejar estado initial
    if active_conversations[user_phone]["state"] == "initial":
        name = active_conversations[user_phone]["name"]
        print(f"📢 Procesando mensaje inicial para {user_phone}, nombre: {name}")
        if name and name != "Desconocido":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Hola, {name}! Soy el asistente de HD Company. 😊 ¿En qué te ayudo hoy?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}
        else:
            active_conversations[user_phone]["state"] = "awaiting_name"
            message = "¡Hola! Soy el asistente de HD Company. 😊 ¿Cuál es tu nombre?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

    # Manejar estado awaiting_name
    if active_conversations[user_phone]["state"] == "awaiting_name":
        name = user_input.strip()
        if re.match(r'^[A-Za-z\s]+$', name) and len(name) <= 50:  # Validar nombre
            save_client(user_phone, name)
            active_conversations[user_phone]["name"] = name
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Encantado, {name}! Soy el asistente de HD Company. 😊 ¿En qué te ayudo hoy?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}
        else:
            message = "Por favor, dime un nombre válido (solo letras y espacios, máx. 50 caracteres). 😊"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

    # Manejar estado awaiting_query
    if active_conversations[user_phone]["state"] == "awaiting_query":
        normalized_menu_options = {
            normalize_text(option["title"]): option["id"] for option in menu_list
        }
        if normalized_input in normalized_menu_options:
            user_input = normalized_menu_options[normalized_input]
            print(f"📢 Mapeando entrada de texto '{normalized_input}' a ID '{user_input}'")

        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Perfecto! 😊 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        # Manejar consultas de disponibilidad
        if any(keyword in normalized_input for keyword in availability_keywords):
            if re.search(r'\b(laptop|computadora)\b', normalized_input):
                products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and p['nombre'].startswith("Laptop")]
                if re.search(r'\b(hp|lenovo|asus|dell|acer)\b', normalized_input):
                    brand = re.search(r'\b(hp|lenovo|asus|dell|acer)\b', normalized_input).group(0).upper()
                    products_in_category = [p for p in products_in_category if brand in p['nombre'].upper()]
                    category_label = f"Laptops {brand}"
                elif re.search(r'\b(gamer|gaming)\b', normalized_input):
                    products_in_category = [p for p in products_in_category if "Gamer" in p['nombre'] or any(spec in p['descripcion'].lower() for spec in ["ryzen 7", "core i7", "16gb", "rtx", "gtx"])]
                    category_label = "Laptops Gamer"
                else:
                    category_label = "Laptops"
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos {category_label.lower()}! 😄\nProductos en {category_label}:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos {category_label.lower()} disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    return {"response": message, "sent_by_app": True}
            elif re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\bimpresoras?\b', normalized_input):
                products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and p['nombre'].startswith("Impresora")]
                if re.search(r'\bt[eé]rmicas?\b', normalized_input):
                    products_in_category = [p for p in products_in_category if "Térmica" in p['nombre']]
                    if products_in_category:
                        product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                        message = f"¡Sí, tenemos impresoras térmicas! 😄\nProductos en Impresoras Térmicas:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                        active_conversations[user_phone]["last_product_list"] = products_in_category
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                        return {"response": message, "sent_by_app": True}
                    else:
                        message = f"Lo siento, no tenemos impresoras térmicas disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                        return {"response": message, "sent_by_app": True}
                elif re.search(r'\bmultifuncional(es)?\b', normalized_input):
                    products_in_category = [p for p in products_in_category if "Multifuncional" in p['nombre'] or all(keyword in p['descripcion'].lower() for keyword in ["imprime", "escanea", "copia"])]
                    if products_in_category:
                        product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                        message = f"¡Sí, tenemos impresoras multifuncionales! 😄\nProductos en Impresoras Multifuncionales:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                        active_conversations[user_phone]["last_product_list"] = products_in_category
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                        return {"response": message, "sent_by_app": True}
                    else:
                        message = f"Lo siento, no tenemos impresoras multifuncionales disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                        return {"response": message, "sent_by_app": True}
                else:
                    if products_in_category:
                        product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                        message = f"¡Sí, tenemos impresoras! 😄\nProductos en Impresoras:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                        active_conversations[user_phone]["last_product_list"] = products_in_category
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                        return {"response": message, "sent_by_app": True}
                    else:
                        message = f"Lo siento, no tenemos impresoras disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                        return {"response": message, "sent_by_app": True}
            elif re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\b(tablets?|tabletas?)\b', normalized_input):
                products_in_category = [p for p in PRODUCTS if p['categoria'] == "Tablets y Celulares" and "Tablet" in p['nombre']]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos tablets! 😄\nProductos en Tablets:\n{product_list}\nSelecciona una tablet o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Tablets y Celulares"
                    active_conversations[user_phone]["last_product_list"] = products_in_category
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos tablets disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    return {"response": message, "sent_by_app": True}
            elif re.search(r'\b(que|cuáles|cuales|qué|muestrame|muéstrame|tienes|presentarme)\b.*\b(accesorios|mouse|teclado|cámara|webcam|disco|monitor|tarjeta de video)\b', normalized_input):
                accessory_categories = ["Mouse y Teclado", "Cámaras Web y Vigilancia", "Discos Duros y Sólidos", "Monitores y TV", "Tarjetas de Video"]
                selected_category = None
                for cat in accessory_categories:
                    if normalize_text(cat).lower() in normalized_input:
                        selected_category = cat
                        break
                if selected_category:
                    products_in_category = [p for p in PRODUCTS if p['categoria'] == selected_category]
                    if products_in_category:
                        product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                        message = f"¡Sí, tenemos {category_short_names.get(selected_category, selected_category).lower()}! 😄\nProductos en {category_short_names.get(selected_category, selected_category)}:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        active_conversations[user_phone]["last_category"] = selected_category
                        active_conversations[user_phone]["last_product_list"] = products_in_category
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                        return {"response": message, "sent_by_app": True}
                    else:
                        message = f"Lo siento, no tenemos {category_short_names.get(selected_category, selected_category).lower()} disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                        return {"response": message, "sent_by_app": True}
                else:
                    message = f"Por favor, especifica qué tipo de accesorios buscas (ej. mouse, teclado, webcam). 😄 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=accessory_categories)
                    return {"response": message, "sent_by_app": True}

        # Manejar selección de categorías
        if user_input == "offers":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "OFERTAS"]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Ofertas:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "OFERTAS"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay ofertas disponibles. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        if user_input == "laptops":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and p['nombre'].startswith("Laptop")]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Laptops:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay laptops disponibles. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        if user_input == "printers":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and p['nombre'].startswith("Impresora")]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Impresoras:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay impresoras disponibles. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        if user_input == "accessories":
            message = f"Tenemos una variedad de tecnología, por favor escoge una categoría:"
            active_conversations[user_phone]["state"] = "awaiting_category"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=accessory_categories)
            return {"response": message, "sent_by_app": True}

        if user_input == "support":
            message = f"📅 Agendar soporte técnico: https://calendly.com/hdcompany/soporte. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        # Manejar FAQs
        faq_match = None
        for faq in FAQS:
            if faq["question"].lower() == "tienen tienda fisica":
                if re.search(r'(d[oó]nde.*(est[aá]n|ubicad[o]?s?|localizad[o]?s?|local|direcci[oó]n))|ubicaci[oó]n|tienda|sucursal|oficina', normalized_input):
                    faq_match = faq
                    break
            elif faq["question"].lower() == "metodos de pago":
                if re.search(r'(pagar|pagos?|tarjeta|paypal|yape|plin)', normalized_input):
                    faq_match = faq
                    break
            elif faq["question"].lower() == "envios":
                if re.search(r'(env[ií]os?|delivery|entrega)', normalized_input):
                    faq_match = faq
                    break
            elif faq["question"].lower() == "contacto":
                if re.search(r'(contacto|tel[eé]fono|whatsapp)', normalized_input):
                    faq_match = faq
                    break
            elif normalized_input in faq["question"].lower():
                faq_match = faq
                break
        if faq_match:
            message = f"{faq_match['answer']} ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        # Manejar selección de producto por nombre o posición
        if re.search(r'\b(primero|primer|segundo|1|2|tercero|3)\b', normalized_input) and active_conversations[user_phone].get("last_product_list"):
            position_map = {"primero": 0, "primer": 0, "1": 0, "segundo": 1, "2": 1, "tercero": 2, "3": 2}
            position = next((position_map[key] for key in position_map if key in normalized_input), None)
            if position is not None and position < len(active_conversations[user_phone]["last_product_list"]):
                selected_product = active_conversations[user_phone]["last_product_list"][position]
                active_conversations[user_phone]["last_product"] = selected_product
                message = f"🛍️ {selected_product['nombre']}: {selected_product['precio']}. Notas: {selected_product['descripcion'][:50]}... ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}

        info = None
        if active_conversations[user_phone].get("last_category"):
            products_in_category = [p for p in PRODUCTS if p['categoria'] == active_conversations[user_phone]["last_category"]]
            for p in products_in_category:
                if user_input.lower() in p['nombre'].lower():
                    info = p
                    break
        if not info:
            for p in PRODUCTS:
                if user_input.lower() in p['nombre'].lower():
                    info = p
                    break

        if info and re.search(r'\b(imagen|foto|ver.*producto|como.*es|puedo.*ver)\b', normalized_input):
            active_conversations[user_phone]["last_product"] = info
            image_path = info.get('image_url', '').lstrip('/') if info.get("image_url") else None
            image_url = f"{BASE_URL}/{image_path}" if image_path else None
            print(f"📢 Intentando enviar imagen: {image_url}")
            if image_url:
                message = f"📷 Imagen de {info['nombre']}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url, buttons=recommendation_options)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
            else:
                print(f"❌ Imagen no encontrada: {image_url}")
                message = f"Lo siento, no tengo imagen de {info['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
        elif info:
            active_conversations[user_phone]["last_product"] = info
            active_conversations[user_phone]["last_category"] = info['categoria']
            message = f"🛍️ {info['nombre']}: {info['precio']}. Notas: {info['descripcion'][:50]}... ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options)
            active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            return {"response": message, "sent_by_app": True}

        # Manejar consultas relacionadas con el carrito
        if re.search(r'\b(ver|mirar|mostrar|quiero ver|carrito|que productos tiene)\b', normalized_input) and "carrito" in normalized_input:
            cart_items = active_conversations[user_phone]["cart"]
            if cart_items:
                total_price = sum(float(item['precio'].replace('PEN ', '')) for item in cart_items)
                cart_list = "\n".join([f"🛍️ {item['nombre']} - Precio: {item['precio']}" for item in cart_items])
                message = (
                    f"🛒 Productos del Carrito:\n"
                    f"{cart_list}\n"
                    f"💵 Total a Pagar: PEN {total_price:.2f}\n"
                    f"{'-' * 55}\n"
                    f"¿Qué deseas hacer, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                )
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=cart_buttons)
                active_conversations[user_phone]["state"] = "awaiting_cart_action"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"😔 Tu carrito está vacío. Selecciona un producto primero."
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        # Consulta a OpenAI
        try:
            recent_messages = active_conversations[user_phone]["messages"][-3:]
            context = "\n".join([f"{msg['sender']}: {msg['message']}" for msg in recent_messages])
            prompt = (
                f"Eres un asistente de HD Company, una tienda de tecnología en Lima, Perú.\n"
                f"Contexto de la conversación:\n{context}\n"
                f"Usa la siguiente información para responder:\n"
                f"- Categorías: {json.dumps(list(set(p['categoria'] for p in PRODUCTS)), ensure_ascii=False)}.\n"
                f"- Productos: {json.dumps(PRODUCTS, ensure_ascii=False)}.\n"
                f"- Descuentos: {json.dumps(DISCOUNTS, ensure_ascii=False)}.\n"
                f"- Último producto recomendado: {active_conversations[user_phone].get('last_product', {}).get('nombre', 'ninguno')}.\n"
                f"Responde en español, amigable, profesional y en máximo 300 caracteres a: '{user_input}'.\n"
                f"- No respondas a 'muéstrame ofertas', 'ver laptops', 'qué impresoras tienes' o similares con recomendaciones; esas consultas se manejan directamente.\n"
                f"- Si pide una recomendación (ej. 'qué laptop me recomiendas', 'quiero una laptop gamer'), sugiere un producto relevante de la categoría adecuada (ej. para laptops, usa 'Laptops y Accesorios' y filtra por 'Laptop' al inicio del nombre; para impresoras, usa 'Impresoras y Accesorios' y filtra por 'Impresora'). Usa el nombre exacto del JSON (ej. 'Laptop LENOVO IDEAPAD 5 ARE05') e incluye su precio.\n"
                f"- Para 'laptop gamer', prioriza laptops con especificaciones altas (ej. Ryzen 7, Core i7, RAM 16GB). Si no hay, elige una laptop disponible.\n"
                f"- Incluye el nombre exacto del producto al final entre corchetes, ej. [Laptop LENOVO IDEAPAD 5 ARE05].\n"
                f"- Asegúrate de incluir el nombre y precio del producto en la respuesta antes de los corchetes, ej. 'Te recomiendo la Laptop LENOVO IDEAPAD 5 ARE05 por PEN 2799.00 [Laptop LENOVO IDEAPAD 5 ARE05]'.\n"
                f"- Si pregunta por el precio (ej. 'cuánto está'), usa el último producto recomendado y devuelve su precio exacto desde el JSON.\n"
                f"- No inventes productos. Si no sabes o no hay contexto, di: 'Lo siento, no tengo esa info. 😅 ¿Otra cosa?'\n"
                f"- Termina con: '¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄'"
            )
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100
            )
            message = response.choices[0].message.content if response.choices else "Lo siento, no tengo esa info. 😅 ¿Otra cosa?"
            found_product = find_product_in_response(message, PRODUCTS, user_input) if message else None
            if found_product:
                active_conversations[user_phone]["last_product"] = found_product
                active_conversations[user_phone]["last_category"] = found_product['categoria']
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            if len(message) > 300:
                message = message[:297] + "..."
            buttons = recommendation_options if found_product or re.search(r'\b(recomendar|sugerir|cual|que|sugiereme|encuentrame)\b', normalized_input) else return_menu_button
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options if buttons == recommendation_options else None, buttons=None if buttons == recommendation_options else buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

    # Manejar estado awaiting_category
    if active_conversations[user_phone]["state"] == "awaiting_category":
        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu" or user_input.lower() == "menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Perfecto! 😊 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        selected_category = None
        category_short_names = {
            "Case y Accesorios": "Case y Accesorios",
            "Cámaras Web y Vigilancia": "Cámaras Web",
            "Discos Duros y Sólidos": "Discos Duros",
            "Monitores y TV": "Monitores",
            "Mouse y Teclado": "Mouse y Teclado",
            "Tarjetas de Video": "Tarjetas de Video",
            "Tablets y Celulares": "Tablets"
        }
        if user_input.startswith("category_"):
            category_id = user_input.replace("category_", "").replace("_", " ")
            selected_category = next((full_name for full_name, short_name in category_short_names.items() if normalize_text(short_name) == normalize_text(category_id)), None)
        else:
            for full_name, short_name in category_short_names.items():
                if normalize_text(short_name) in normalized_input or normalized_input in normalize_text(full_name):
                    selected_category = full_name
                    break

        if selected_category:
            products_in_category = [p for p in PRODUCTS if p['categoria'] == selected_category]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category[:5]])
                message = f"Productos en {selected_category}:\n{product_list}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = selected_category
                active_conversations[user_phone]["last_product_list"] = products_in_category
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay productos disponibles en {selected_category}. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                active_conversations[user_phone]["state"] = "awaiting_query"
                return {"response": message, "sent_by_app": True}

        try:
            recent_messages = active_conversations[user_phone]["messages"][-3:]
            context = "\n".join([f"{msg['sender']}: {msg['message']}" for msg in recent_messages])
            prompt = (
                f"Eres un asistente de HD Company, una tienda de tecnología en Lima, Perú.\n"
                f"Contexto de la conversación:\n{context}\n"
                f"Usa la siguiente información para responder:\n"
                f"- Categorías: {json.dumps(list(set(p['categoria'] for p in PRODUCTS)), ensure_ascii=False)}.\n"
                f"- Productos: {json.dumps(PRODUCTS, ensure_ascii=False)}.\n"
                f"- Descuentos: {json.dumps(DISCOUNTS, ensure_ascii=False)}.\n"
                f"- Último producto recomendado: {active_conversations[user_phone].get('last_product', {}).get('nombre', 'ninguno')}.\n"
                f"Responde en español, amigable, profesional y en máximo 300 caracteres a: '{user_input}'.\n"
                f"- No respondas a 'muéstrame ofertas', 'ver laptops', 'qué impresoras tienes' o similares con recomendaciones; esas consultas se manejan directamente.\n"
                f"- Si pide una recomendación (ej. 'qué laptop me recomiendas', 'quiero una laptop gamer'), sugiere un producto relevante de la categoría adecuada (ej. para laptops, usa 'Laptops y Accesorios' y filtra por 'Laptop' al inicio del nombre; para impresoras, usa 'Impresoras y Accesorios' y filtra por 'Impresora'). Usa el nombre exacto del JSON (ej. 'Laptop LENOVO IDEAPAD 5 ARE05') e incluye su precio.\n"
                f"- Para 'laptop gamer', prioriza laptops con especificaciones altas (ej. Ryzen 7, Core i7, RAM 16GB). Si no hay, elige una laptop disponible.\n"
                f"- Incluye el nombre exacto del producto al final entre corchetes, ej. [Laptop LENOVO IDEAPAD 5 ARE05].\n"
                f"- Asegúrate de incluir el nombre y precio del producto en la respuesta antes de los corchetes, ej. 'Te recomiendo la Laptop LENOVO IDEAPAD 5 ARE05 por PEN 2799.00 [Laptop LENOVO IDEAPAD 5 ARE05]'.\n"
                f"- Si pregunta por el precio (ej. 'cuánto está'), usa el último producto recomendado y devuelve su precio exacto desde el JSON.\n"
                f"- No inventes productos. Si no sabes o no hay contexto, di: 'Lo siento, no tengo esa info. 😅 ¿Otra cosa?'\n"
                f"- Termina con: '¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄'"
            )
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100
            )
            message = response.choices[0].message.content if response.choices else "Lo siento, no tengo esa info. 😅 ¿Otra cosa?"
            found_product = find_product_in_response(message, PRODUCTS, user_input) if message else None
            if found_product:
                active_conversations[user_phone]["last_product"] = found_product
                active_conversations[user_phone]["last_category"] = found_product['categoria']
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            if len(message) > 300:
                message = message[:297] + "..."
            buttons = recommendation_options if found_product or re.search(r'\b(recomendar|sugerir|cual|que|sugiereme|encuentrame)\b', normalized_input) else return_menu_button
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=recommendation_options if buttons == recommendation_options else None, buttons=None if buttons == recommendation_options else buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)