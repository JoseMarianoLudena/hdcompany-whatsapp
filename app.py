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

load_dotenv()
app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'images'
@app.route('/images/<path:filename>')
def serve_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecretkey')
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# URL base para imágenes (ngrok localmente, Render en producción)
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')  # Ejemplo: https://abc123.ngrok-free.app

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
            "last_product": data.get("last_product", None)
        }
    return cleaned

def send_whatsapp_message(to_phone, message=None, image_url=None, buttons=None):
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
        payload["type"] = "image"
        payload["image"] = {
            "link": image_url,
            "caption": message or ""
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
                    "last_product": None
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
        "mouse": "Mouse / Teclado / Pad Mouse / Kit",
        "teclado": "Mouse / Teclado / Pad Mouse / Kit",
        "monitor": "Monitor / TV & Accesorios",
        "case": "Case y Accesorios",
        "cámara": "Cámaras Web & Vídeo Vigilancia",
        "disco": "Discos Duros / Discos Sólidos",
        "impresora": "Impresoras y Accesorios",
        "tarjeta": "Tarjetas de Vídeos",
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
        filtered_products = [p for p in products if p['categoria'] == target_category]
        print(f"📢 Filtrando productos por categoría: {target_category}")

    # Buscar el producto más relevante
    best_match = None
    best_score = 0
    for product in filtered_products:
        normalized_product_name = normalize_text(product['nombre'])
        product_words = normalized_product_name.split()
        # Calcular un puntaje de coincidencia basado en palabras clave
        score = 0
        for word in product_words:
            if len(word) > 3 and word in normalized_response:
                score += 1
        # También considerar coincidencia del nombre completo
        if normalized_product_name in normalized_response:
            score += len(product_words)  # Dar mayor peso a coincidencia completa
        print(f"📢 Evaluando producto: {product['nombre']} (score: {score})")
        if score > best_score:
            best_match = product
            best_score = score

    if best_match:
        print(f"📢 Producto encontrado: {best_match['nombre']} en respuesta: {response_text}")
        return best_match
    print(f"📢 No se encontró producto en respuesta: {response_text}")
    return None

def handle_user_input(user_input, user_phone):
    close_keywords = ["gracias", "resuelto", "listo", "ok", "solucionado"]
    escalation_keywords = ["agente", "humano", "persona", "hablar con alguien"]
    greeting_keywords = ["hola", "qué tal", "buenos días", "buenas tardes", "buenas noches", "hey", "saludos"]
    product_keywords = ["producto", "artículo", "cargador", "mouse", "laptop", "productos", "lista"]
    more_info_keywords = ["más información", "más detalles", "sí", "si", "mas info", "detalles", "more_info"]

    menu_buttons = [
        {"id": "products", "title": "Productos"},
        {"id": "support", "title": "Soporte Técnico"},
        {"id": "agent", "title": "Hablar con Agente"}
    ]

    info_menu_buttons = [
        {"id": "more_info", "title": "Más información"},
        {"id": "return_menu", "title": "Regresar al menú"}
    ]

    if user_phone not in active_conversations:
        print(f"📢 Inicializando nueva conversación para {user_phone}")
        active_conversations[user_phone] = {
            "messages": [],
            "escalated": False,
            "state": "initial",
            "name": get_client_name(user_phone),
            "last_product": None
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
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}
        else:
            active_conversations[user_phone]["state"] = "awaiting_name"
            message = "¡Hola! Soy el asistente de HD Company. 😊 ¿Cuál es tu nombre?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

    if active_conversations[user_phone]["state"] == "awaiting_name":
        name = user_input.strip()
        save_client(user_phone, name)
        active_conversations[user_phone]["name"] = name
        active_conversations[user_phone]["state"] = "awaiting_query"
        message = f"¡Encantado, {name}! Soy el asistente de HD Company. 😊 ¿En qué te ayudo hoy?"
        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
        return {"response": message, "sent_by_app": True}

    if active_conversations[user_phone]["state"] == "awaiting_menu_confirmation":
        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = "¡Perfecto! 😊 ¿En qué te ayudo ahora?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}
        # Manejar solicitud de imagen
        if re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input):
            if active_conversations[user_phone].get("last_product"):
                product = active_conversations[user_phone]["last_product"]
                image_url = f"{BASE_URL}{product['image_url']}" if product.get("image_url") else None
                if image_url:
                    message = f"📷 Imagen de {product['nombre']} ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url, buttons=menu_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_query"  # Volver a awaiting_query
                    return {"response": message, "sent_by_app": True}
                else:
                    message = f"Lo siento, no tengo imagen de {product['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
                    active_conversations[user_phone]["state"] = "awaiting_query"  # Volver a awaiting_query
                    return {"response": message, "sent_by_app": True}
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}
        # Manejar "more_info"
        if any(keyword in normalized_input for keyword in more_info_keywords) or user_input == "more_info":
            if active_conversations[user_phone].get("last_product"):
                info = active_conversations[user_phone]["last_product"]
                message = f"🛍️ {info['nombre']}: {info['descripcion']}. 💻 ¿Regresar al menú?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=info_menu_buttons)
                return {"response": message, "sent_by_app": True}
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}
        # Si no es una solicitud conocida, volver a awaiting_query y procesar como nueva consulta
        active_conversations[user_phone]["state"] = "awaiting_query"
        return handle_user_input(user_input, user_phone)  # Reprocesar el input en awaiting_query

    if active_conversations[user_phone]["state"] == "awaiting_query":
        # FAQs
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
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

        # Productos y Categorías
        if re.search(r'(productos|categor[ií]as?|tipo[s]? de productos?|qu[eé].*tienes?)', normalized_input) or user_input == "products":
            categories = sorted(list(set(p['categoria'] for p in PRODUCTS)))
            message = f"Escoge una categoría: {', '.join(categories)}. 😄 Escribe la categoría que quieras ver."
            active_conversations[user_phone]["state"] = "awaiting_category"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message)
            return {"response": message, "sent_by_app": True}

        # Producto más barato de la categoría listada
        if re.search(r'\b(mas barato|más barato|barato de esos|economicos de esos|mas economico|más economico|mas economicos)\b', normalized_input) and active_conversations[user_phone].get("last_category"):
            category = active_conversations[user_phone]["last_category"]
            products_in_category = [p for p in PRODUCTS if p['categoria'] == category]
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
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
                return {"response": message, "sent_by_app": True}

        # Soporte Técnico
        if user_input == "support":
            message = f"📅 Agendar soporte técnico: https://calendly.com/hdcompany/soporte. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

        # Más información sobre producto
        if any(keyword in normalized_input for keyword in more_info_keywords) or user_input == "more_info":
            if active_conversations[user_phone].get("last_product"):
                info = active_conversations[user_phone]["last_product"]
                message = f"🛍️ {info['nombre']}: {info['descripcion']}. 💻 ¿Regresar al menú?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=info_menu_buttons)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}

        # Producto específico o solicitud de imagen de producto específico
        info = next((p for p in PRODUCTS if normalized_input in normalize_text(p['nombre'])), None)
        if info and re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input):
            active_conversations[user_phone]["last_product"] = info
            image_url = f"{BASE_URL}{info['image_url']}" if info.get("image_url") else None
            if image_url:
                message = f"📷 Imagen de {info['nombre']} ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url, buttons=menu_buttons)
            else:
                message = f"Lo siento, no tengo imagen de {info['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}
        elif info:
            active_conversations[user_phone]["last_product"] = info
            message = f"🛍️ {info['nombre']}: {info['precio']}. Notas: {info['descripcion'][:50]}... 💻 ¿Más info o regresar al menú?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=info_menu_buttons)
            active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
            return {"response": message, "sent_by_app": True}

        # Selección de producto por posición (ej. "Quiero el primero")
        if re.search(r'\b(primero|primer|1)\b', normalized_input) and active_conversations[user_phone].get("last_category"):
            category = active_conversations[user_phone]["last_category"]
            products_in_category = [p for p in PRODUCTS if p['categoria'] == category]
            if products_in_category:
                selected_product = products_in_category[0]
                active_conversations[user_phone]["last_product"] = selected_product
                message = f"🛍️ {selected_product['nombre']}: {selected_product['precio']}. Notas: {selected_product['descripcion'][:50]}... 💻 ¿Más info o regresar al menú?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=info_menu_buttons)
                active_conversations[user_phone]["state"] = "awaiting_menu_confirmation"
                return {"response": message, "sent_by_app": True}

        # Solicitud de imagen
        if re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input) and active_conversations[user_phone].get("last_product"):
            product = active_conversations[user_phone]["last_product"]
            image_url = f"{BASE_URL}{product['image_url']}" if product.get("image_url") else None
            if image_url:
                message = f"📷 Imagen de {product['nombre']} ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, image_url=image_url, buttons=menu_buttons)
            else:
                message = f"Lo siento, no tengo imagen de {product['nombre']}. 😅 Visita https://mitienda.today/hdcompany para verlo. ¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}
        elif re.search(r'\b(imagen|foto|ver.*producto|cómo.*es|puedo.*ver)\b', normalized_input):
            return {"response": "😔 No hay un producto reciente seleccionado. Escribe el nombre de un producto o pide una recomendación.", "sent_by_app": True}

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
                f"Responde en español, amigable, profesional y en máximo 300 caracteres a: '{user_input}'.\n"
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
            message = response.choices[0].message.content

            # Actualizar last_product con coincidencia específica
            found_product = find_product_in_response(message, PRODUCTS, user_input)
            active_conversations[user_phone]["last_product"] = found_product

            if len(message) > 300:
                message = message[:297] + "..."
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}
        except Exception as e:
            print(f"❌ Error con OpenAI: {str(e)}")
            message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

    if active_conversations[user_phone]["state"] == "awaiting_category":
        if re.search(r'\b(regresar|volver)\s*(al)?\s*(menu|menú)\b', normalized_input) or user_input == "return_menu" or user_input.lower() == "menu":
            active_conversations[user_phone]["state"] = "awaiting_query"
            message = "¡Perfecto! 😊 ¿En qué te ayudo ahora?"
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

        category_match = next((p for p in PRODUCTS if normalized_input in normalize_text(p['categoria'])), None)
        if category_match:
            products_in_category = [p for p in PRODUCTS if p['categoria'] == category_match['categoria']]
            product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category[:5]])
            message = f"Productos en {category_match['categoria']}:\n{product_list}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
            active_conversations[user_phone]["state"] = "awaiting_query"
            active_conversations[user_phone]["last_category"] = category_match['categoria']
            if products_in_category:
                active_conversations[user_phone]["last_product"] = products_in_category[0]
            result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
            return {"response": message, "sent_by_app": True}

        # Consulta a OpenAI para entradas complejas
        complex_query = (
            re.search(r'\b(recomendar|sugerir|cuál|que|qué)\b', normalized_input) or
            len(normalized_input.split()) > 3
        )
        if complex_query:
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
                    f"Responde en español, amigable, profesional y en máximo 300 caracteres a: '{user_input}'.\n"
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
                message = response.choices[0].message.content

                # Actualizar last_product con coincidencia específica
                found_product = find_product_in_response(message, PRODUCTS, user_input)
                active_conversations[user_phone]["last_product"] = found_product

                if len(message) > 300:
                    message = message[:297] + "..."
                active_conversations[user_phone]["state"] = "awaiting_query"  # Volver a awaiting_query
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
                return {"response": message, "sent_by_app": True}
            except Exception as e:
                print(f"❌ Error con OpenAI: {str(e)}")
                message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí. 😅 ¿Más detalles o elige una opción?"
                result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
                return {"response": message, "sent_by_app": True}

        category_keywords = {
            "case": "Case y Accesorios",
            "cámara": "Cámaras Web & Vídeo Vigilancia",
            "disco": "Discos Duros / Discos Sólidos",
            "impresora": "Impresoras y Accesorios",
            "laptop": "Laptops y Accesorios",
            "monitor": "Monitor / TV & Accesorios",
            "mouse": "Mouse / Teclado / Pad Mouse / Kit",
            "teclado": "Mouse / Teclado / Pad Mouse / Kit",
            "tablet": "Tablets y Celulares",
            "celular": "Tablets y Celulares",
            "tarjeta": "Tarjetas de Vídeos",
            "oferta": "OFERTAS"
        }

        for keyword, category in category_keywords.items():
            if keyword == normalized_input:  # Coincidencia exacta con palabra clave
                category_match = next((p for p in PRODUCTS if p['categoria'] == category), None)
                if category_match:
                    products_in_category = [p for p in PRODUCTS if p['categoria'] == category_match['categoria']]
                    product_list = "\n".join([f"- {p['nombre']} - {p['precio']}" for p in products_in_category[:5]])
                    message = f"Productos en {category_match['categoria']}:\n{product_list}\n¿En qué te ayudo ahora, {active_conversations[user_phone]['name'] or 'Ko'}? 😄"
                    active_conversations[user_phone]["state"] = "awaiting_query"
                    active_conversations[user_phone]["last_category"] = category_match['categoria']
                    if products_in_category:
                        active_conversations[user_phone]["last_product"] = products_in_category[0]
                    result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
                    return {"response": message, "sent_by_app": True}

        # Si no coincide con ninguna categoría, pedir aclaración
        message = f"Lo siento, {active_conversations[user_phone]['name'] or 'Ko'}, no entendí la categoría. 😅 Por favor, elige una: {', '.join(sorted(list(set(p['categoria'] for p in PRODUCTS))))}."
        result = send_whatsapp_message(f"whatsapp:{user_phone}", message, buttons=menu_buttons)
        return {"response": message, "sent_by_app": True}

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)