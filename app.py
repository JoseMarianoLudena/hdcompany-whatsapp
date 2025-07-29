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

WHATSAPP_PHONE_NUMBER_ID = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
WHATSAPP_ACCESS_TOKEN = os.getenv('WHATSAPP_ACCESS_TOKEN')

load_dotenv()
print(f"📢 BASE_URL cargada: {os.getenv('BASE_URL')}")
app = Flask(__name__, static_folder='images', static_url_path='/images')
app.config['UPLOAD_FOLDER'] = 'images'
@app.route('/images/<path:filename>')
def serve_image(filename):
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

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# URL base para imágenes (ngrok localmente, Render en producción)
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')

@app.route("/")
def home():
    return "¡La aplicación está corriendo correctamente!"

# Configurar OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("Falta OPENAI_API_KEY en .env")

# Cargar datos de HD Company
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
PRODUCTS = json.load(open(os.path.join(DATA_DIR, 'products.json'), 'r', encoding='utf-8'))
FAQS = json.load(open(os.path.join(DATA_DIR, 'faqs.json'), 'r', encoding='utf-8'))
DISCOUNTS = json.load(open(os.path.join(DATA_DIR, 'discounts.json'), 'r', encoding='utf-8'))

active_conversations = {}

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

def init_db():
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

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(id=user_data[0], username=user_data[1])
        return None

def save_client(user_phone, name):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO clients (user_phone, name, timestamp) VALUES (?, ?, ?)",
                  (user_phone, name or "Desconocido", timestamp))
        conn.commit()

def get_client_name(user_phone):
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM clients WHERE user_phone = ?", (user_phone,))
        result = c.fetchone()
        return result[0] if result else None

def get_all_clients():
    with sqlite3.connect("clients.db") as conn:
        c = conn.cursor()
        c.execute("SELECT user_phone, name, timestamp FROM clients ORDER BY timestamp DESC")
        return c.fetchall()

def clean_conversations(conversations):
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

def send_whatsapp_message(to_phone, message=None, image_url=None, buttons=None, list_menu=None):
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
        # Verificar si el archivo existe en el servidor
        file_name = image_url.split('/')[-1]
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        print(f"📢 Verificando archivo en: {full_path}")
        if os.path.exists(full_path):
            # Enviar solo la imagen
            image_payload = {
                "messaging_product": "whatsapp",
                "to": to_phone.replace("whatsapp:", ""),
                "type": "image",
                "image": {
                    "link": image_url
                }
            }
            print(f"📢 Enviando imagen incrustada: {json.dumps(image_payload, ensure_ascii=False)}")
            image_response = requests.post(
                f"https://graph.facebook.com/v20.0/{os.getenv('WHATSAPP_PHONE_NUMBER_ID')}/messages",
                headers={"Authorization": f"Bearer {os.getenv('WHATSAPP_ACCESS_TOKEN')}"},
                json=image_payload
            )
            print(f"📢 Respuesta de WhatsApp API (imagen): {image_response.status_code} {image_response.text}")
            if image_response.status_code == 200:
                # Enviar mensaje de texto por separado
                text_payload = {
                    "messaging_product": "whatsapp",
                    "to": to_phone.replace("whatsapp:", ""),
                    "type": "text",
                    "text": {"body": message}
                }
                text_response = requests.post(
                    f"https://graph.facebook.com/v20.0/{os.getenv('WHATSAPP_PHONE_NUMBER_ID')}/messages",
                    headers={"Authorization": f"Bearer {os.getenv('WHATSAPP_ACCESS_TOKEN')}"},
                    json=text_payload
                )
                print(f"📢 Respuesta de WhatsApp API (texto): {text_response.status_code} {text_response.text}")
                return {"status": "success", "message_id": image_response.json().get("messages", [{}])[0].get("id", "")}
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

@app.route("/login", methods=["GET", "POST"])
def login():
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

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/process", methods=["POST"])
def process_message():
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

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
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
                    "last_category": None
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

@app.route("/clients", methods=["GET"])
@login_required
def clients():
    clients = get_all_clients()
    return render_template("clients.html", clients=clients, current_user=current_user)

@socketio.on('connect', namespace='/dashboard')
def handle_connect():
    print("📢 Cliente conectado al dashboard")
    emit('update_conversations', clean_conversations(active_conversations), namespace='/dashboard')

def normalize_text(text):
    text = ''.join(c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn')
    return text.lower().strip()

def find_product_in_response(response_text, products, user_input):
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
        "cámara": "Cámaras Web y Vigilancia",
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

    # Filtrar productos por categoría si se identificó una
    filtered_products = products
    if target_category:
        if target_category == "Laptops y Accesorios":
            filtered_products = [p for p in products if p['categoria'] == target_category and "Laptop" in p['nombre']]
        elif target_category == "Impresoras y Accesorios":
            filtered_products = [p for p in products if p['categoria'] == target_category and "Impresora" in p['nombre']]
        else:
            filtered_products = [p for p in products if p['categoria'] == target_category]
        print(f"📢 Filtrando productos por categoría: {target_category}")

    # Usar difflib para encontrar coincidencias cercanas
    product_names = [p['nombre'] for p in filtered_products]
    response_product_name = None
    # Extraer el nombre del producto entre corchetes, si existe
    match = re.search(r'\[(.*?)\]', normalized_response)
    if match:
        response_product_name = match.group(1)
    else:
        # Buscar coincidencias cercanas en el texto completo
        words = normalized_response.split()
        potential_names = [' '.join(words[i:i+5]) for i in range(len(words)-4)]
        for name in potential_names:
            matches = difflib.get_close_matches(normalize_text(name), [normalize_text(p['nombre']) for p in filtered_products], n=1, cutoff=0.6)
            if matches:
                response_product_name = matches[0]
                break

    if response_product_name:
        for product in filtered_products:
            if normalize_text(product['nombre']) == normalize_text(response_product_name):
                print(f"📢 Producto encontrado: {product['nombre']} en respuesta: {response_text}")
                return product
            # Verificar coincidencias cercanas
            matches = difflib.get_close_matches(normalize_text(response_product_name), [normalize_text(product['nombre'])], n=1, cutoff=0.7)
            if matches and normalize_text(product['nombre']) == matches[0]:
                print(f"📢 Producto encontrado (coincidencia cercana): {product['nombre']} en respuesta: {response_text}")
                return product

    print(f"📢 No se encontró producto en respuesta: {response_text}")
    return None

def find_product_by_name_or_position(user_input, products, last_category=None):
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

def handle_user_input(user_input, user_phone):
    close_keywords = ["gracias", "resuelto", "listo", "ok", "solucionado"]
    escalation_keywords = ["agente", "humano", "persona", "hablar con alguien"]
    greeting_keywords = ["hola", "qué tal", "buenos días", "buenas tardes", "buenas noches", "hey", "saludos"]
    availability_keywords = ["tienes", "hay", "dispones", "existen"]
    more_info_keywords = ["más información", "más detalles", "sí", "si", "mas info", "detalles", "more_info"]

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

    return_menu_button = [
        {"id": "return_menu", "title": "Regresar al Menú"}
    ]

    accessory_categories = [
        {"id": "category_case", "title": "Case y Accesorios"},
        {"id": "category_cameras", "title": "Cámaras Web y Vigilancia"},
        {"id": "category_disks", "title": "Discos Duros y Sólidos"},
        {"id": "category_monitors", "title": "Monitores y TV"},
        {"id": "category_mouse_keyboard", "title": "Mouse y Teclado"},
        {"id": "category_video_cards", "title": "Tarjetas de Video"},
        {"id": "category_tablets", "title": "Tablets y Celulares"}
    ]

    if user_phone not in active_conversations:
        print(f"📢 Inicializando nueva conversación para {user_phone}")
        active_conversations[user_phone] = {
            "messages": [],
            "escalated": False,
            "state": "initial",
            "name": get_client_name(user_phone),
            "last_product": {},
            "last_category": None
        }

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

    if any(keyword in user_input.lower() for keyword in close_keywords):
        print(f"📢 Cerrando conversación para {user_phone}")
        response = "¡Gracias por contactarnos! 😊 Escríbenos si necesitas más ayuda."
        del active_conversations[user_phone]
        socketio.emit('close_conversation', {'user_phone': user_phone}, namespace='/dashboard')
        return {"response": response}

    if active_conversations[user_phone]["escalated"]:
        print(f"📢 Conversación escalada para {user_phone}, ignorando mensaje")
        return {"response": ""}

    if any(keyword in user_input.lower() for keyword in escalation_keywords) or user_input == "agent":
        print(f"📢 Escalando conversación para {user_phone}")
        active_conversations[user_phone]["escalated"] = True
        send_whatsapp_message(os.getenv("AGENT_PHONE_NUMBER", "whatsapp:+51992436107"), f"🔔 Nueva solicitud de agente humano!\nUsuario: {user_phone}\nMensaje: {user_input}")
        return {"response": "🔔 Te conecto con un agente. ¡Un momento! 😊"}

    normalized_input = normalize_text(user_input)
    print(f"📢 Input normalizado: {normalized_input}, estado: {active_conversations[user_phone]['state']}")
    if any(keyword in normalized_input for keyword in greeting_keywords) and active_conversations[user_phone]["state"] == "initial":
        name = active_conversations[user_phone]["name"]
        print(f"📢 Procesando saludo para {user_phone}, nombre: {name}")
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

    if active_conversations[user_phone]["state"] == "awaiting_name":
        name = user_input.strip()
        save_client(user_phone, name)
        active_conversations[user_phone]["name"] = name
        active_conversations[user_phone]["state"] = "awaiting_query"
        message = f"¡Encantado, {name}! Soy el asistente de HD Company. 😊 ¿En qué te ayudo hoy?"
        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
        return {"response": message, "sent_by_app": True}

    if active_conversations[user_phone]["state"] == "awaiting_menu_confirmation":
        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = f"¡Perfecto! 😊 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}
        # Manejar solicitud de imagen
        if re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input) or user_input == "view_image":
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                image_path = product.get('image_url', '').lstrip('/') if product.get("image_url") else None
                image_url = f"{BASE_URL}/{image_path}" if image_path else None
                print(f"📢 Intentando enviar imagen: {image_url}")
                if image_url:
                    message = f"📷 Imagen de {product['nombre']}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url)
                    print(f"📢 Imagen enviada sin verificación, resultado: {result}")
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
                else:
                    print(f"❌ Imagen no encontrada o URL inválida: {image_url}")
                    message = f"Lo siento, no tengo imagen de {product['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
        # Manejar "view_specs"
        if any(keyword in normalized_input for keyword in more_info_keywords) or user_input == "view_specs":
            if active_conversations[user_phone].get("last_product"):
                info = active_conversations[user_phone]["last_product"]
                message = f"🛍️ {info['nombre']}: {info['descripcion']}. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                return {"response": message, "sent_by_app": True}
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}
        # Consulta a OpenAI para cualquier otra entrada
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
                f"- Si pide una recomendación (ej. 'qué laptop me recomiendas', 'quiero una laptop gamer'), sugiere un producto relevante de la categoría adecuada (ej. para laptops, usa 'Laptops y Accesorios' y filtra por 'Laptop' en el nombre; para impresoras, usa 'Impresoras y Accesorios' y filtra por 'Impresora'). Usa el nombre exacto del JSON (ej. 'Laptop LENOVO IDEAPAD 5 ARE05') e incluye su precio.\n"
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
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            if len(message) > 300:
                message = message[:297] + "..."
            buttons = product_buttons if found_product or re.search(r'\b(recomendar|sugerir|cuál|cual|que|qué|sugiereme|encuentrame)\b', normalized_input) else return_menu_button            
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

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

        if any(keyword in normalized_input for keyword in availability_keywords):
            if "laptop" in normalized_input or "computadora" in normalized_input:
                products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and "Laptop" in p['nombre']]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos laptops! 😄\nProductos en Laptops:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos laptops disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    return {"response": message, "sent_by_app": True}
            elif "impresora" in normalized_input:
                products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and "Impresora" in p['nombre']]
                if products_in_category:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                    message = f"¡Sí, tenemos impresoras! 😄\nProductos en Impresoras:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
                    active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tenemos impresoras disponibles ahora. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                    return {"response": message, "sent_by_app": True}

        if user_input == "offers":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "OFERTAS"]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Ofertas:\n{product_list}\nSelecciona un producto o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "OFERTAS"
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay ofertas disponibles. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        if user_input == "laptops":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Laptops y Accesorios" and "Laptop" in p['nombre']]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Laptops:\n{product_list}\nSelecciona una laptop o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Laptops y Accesorios"
                active_conversations[user_phone]["last_product"] = products_in_category[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=return_menu_button)
                return {"response": message, "sent_by_app": True}
            else:
                message = f"Lo siento, no hay laptops disponibles. 😅 ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
                return {"response": message, "sent_by_app": True}

        if user_input == "printers":
            products_in_category = [p for p in PRODUCTS if p['categoria'] == "Impresoras y Accesorios" and "Impresora" in p['nombre']]
            if products_in_category:
                product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category])
                message = f"Productos en Impresoras:\n{product_list}\nSelecciona una impresora o escribe su nombre.\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_category"] = "Impresoras y Accesorios"
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

        faq_match = None
        for faq in FAQS:
            if faq["question"].lower() == "tienen tienda física":
                if re.search(r'(d[oó]nde.*(est[aá]n|ubicad[o]?s?|localizad[o]?s?|local|direcci[oó]n))|ubicaci[oó]n|tienda|sucursal', normalized_input):
                    faq_match = faq
                    break
            elif faq["question"].lower() == "métodos de pago":
                if re.search(r'(pagar|pagos?|tarjeta|paypal|yape|plin)', normalized_input):
                    faq_match = faq
                    break
            elif faq["question"].lower() == "envíos":
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

        info = find_product_by_name_or_position(user_input, PRODUCTS, active_conversations[user_phone].get("last_category"))

        if info and re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input):
            active_conversations[user_phone]["last_product"] = info
            image_path = info.get('image_url', '').lstrip('/') if info.get("image_url") else None
            image_url = f"{BASE_URL}/{image_path}" if image_path else None
            print(f"📢 Intentando enviar imagen: {image_url}")
            file_name = image_path.split('/')[-1] if image_path else None
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name) if file_name else None
            print(f"📢 Verificando archivo en: {full_path}")
            if image_url and full_path and os.path.exists(full_path):
                message = f"📷 Imagen de {info['nombre']}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
            else:
                print(f"❌ Imagen no encontrada o URL inválida: {image_url}, path: {full_path}")
                message = f"Lo siento, no tengo imagen de {info['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
        elif info:
            active_conversations[user_phone]["last_product"] = info
            message = f"🛍️ {info['nombre']}: {info['precio']}. Notas: {info['descripcion'][:50]}... ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
            active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            return {"response": message, "sent_by_app": True}

        if re.search(r'\b(primero|primer|segundo|1|2|tercero|3)\b', normalized_input) and active_conversations[user_phone].get("last_category"):
            selected_product = find_product_by_name_or_position(user_input, PRODUCTS, active_conversations[user_phone]["last_category"])
            if selected_product:
                active_conversations[user_phone]["last_product"] = selected_product
                message = f"🛍️ {selected_product['nombre']}: {selected_product['precio']}. Notas: {selected_product['descripcion'][:50]}... ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}

        # Manejar solicitud de imagen
        if re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input) or user_input == "view_image":
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                image_path = product.get('image_url', '').lstrip('/') if product.get("image_url") else None
                image_url = f"{BASE_URL}/{image_path}" if image_path else None
                print(f"📢 Intentando enviar imagen: {image_url}")
                if image_url:
                    message = f"📷 Imagen de {product['nombre']}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url)
                    print(f"📢 Imagen enviada sin verificación, resultado: {result}")
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
                else:
                    print(f"❌ Imagen no encontrada o URL inválida: {image_url}")
                    message = f"Lo siento, no tengo imagen de {product['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                    return {"response": message, "sent_by_app": True}
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}

        if re.search(r'(productos|categor[ií]as?|tipo[s]? de productos?|qu[eé].*tienes?)', normalized_input):
            message = f"📋 Elige una opción para ver productos o servicios:"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

        if re.search(r'\b(mas barato|más barato|barato de esos|economicos de esos|mas economico|más economico|mas economicos)\b', normalized_input) and active_conversations[user_phone].get("last_category"):
            category = active_conversations[user_phone]["last_category"]
            products_in_category = [p for p in PRODUCTS if p['categoria'] == category]
            if category == "Laptops y Accesorios":
                products_in_category = [p for p in products_in_category if "Laptop" in p['nombre']]
            elif category == "Impresoras y Accesorios":
                products_in_category = [p for p in products_in_category if "Impresora" in p['nombre']]
            if products_in_category:
                cheapest_products = sorted(products_in_category, key=lambda p: float(p['precio'].replace('PEN ', '')))
                cheapest_price = float(cheapest_products[0]['precio'].replace('PEN ', ''))
                cheapest = [p for p in cheapest_products if float(p['precio'].replace('PEN ', '')) == cheapest_price]
                if len(cheapest) > 1:
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in cheapest])
                    message = f"Productos más baratos en {category}:\n{product_list}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                else:
                    message = f"El más barato en {category} es {cheapest[0]['nombre']} - {cheapest[0]['precio']}. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                active_conversations[user_phone]["last_product"] = cheapest[0]
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=product_buttons)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
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
                f"- Si pide una recomendación (ej. 'qué laptop me recomiendas', 'quiero una laptop gamer'), sugiere un producto relevante de la categoría adecuada (ej. para laptops, usa 'Laptops y Accesorios' y filtra por 'Laptop' en el nombre; para impresoras, usa 'Impresoras y Accesorios' y filtra por 'Impresora'). Usa el nombre exacto del JSON (ej. 'Laptop LENOVO IDEAPAD 5 ARE05') e incluye su precio.\n"
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
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            if len(message) > 300:
                message = message[:297] + "..."
            buttons = product_buttons if found_product or re.search(r'\b(recomendar|sugerir|cuál|cual|que|qué|sugiereme|encuentrame)\b', normalized_input) else return_menu_button
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

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
                f"- Si pide una recomendación (ej. 'qué laptop me recomiendas'), sugiere un producto adecuado de la categoría correspondiente (ej. 'Laptops y Accesorios' para laptops).\n"
                f"- Usa el nombre exacto del producto según el JSON proporcionado.\n"
                f"- Si no hay info, di: 'Lo siento, no tengo esa info. 😅 ¿Otra cosa?'\n"
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
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            if len(message) > 300:
                message = message[:297] + "..."
            buttons = product_buttons if found_product else return_menu_button
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, list_menu=menu_list)
            return {"response": message, "sent_by_app": True}

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)