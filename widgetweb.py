from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO, emit
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# Simulación de la base de datos de productos
products = [
    {"id": "iphone", "title": "Iphone 17 Pro Max"},
    {"id": "dior", "title": "Dior Perfume"},
    {"id": "nike", "title": "Zapatillas Nike"}
]

# Simulación de horarios
schedules = [
    {"id": "monday_10am", "title": "Lunes 10:00 AM"},
    {"id": "tuesday_2pm", "title": "Martes 2:00 PM"},
    {"id": "wednesday_9am", "title": "Miércoles 9:00 AM"},
    {"id": "thursday_3pm", "title": "Jueves 3:00 PM"},
    {"id": "friday_11am", "title": "Viernes 11:00 AM"}
]

@app.route('/')
def index():
    return render_template('demo.html')

@socketio.on('connect', namespace='/chat')
def handle_connect():
    print('📢 Cliente conectado al chat de demo')
    emit('message', {'response': '¡Hola! Soy tu asistente virtual para negocios. 😊 ¿Cuál es tu nombre?'})

@socketio.on('message', namespace='/chat')
def handle_message(data):
    text = data['text'].lower().strip()
    user_id = data['user_id']
    print(f'📢 Procesando mensaje web de {user_id}: {text}')

    response = None
    buttons = []

    if not hasattr(handle_message, 'user_state'):
        handle_message.user_state = {}

    if user_id not in handle_message.user_state:
        handle_message.user_state[user_id] = {'step': 'initial', 'name': None}

    state = handle_message.user_state[user_id]

    if state['step'] == 'initial':
        state['name'] = text
        response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
        buttons = [
            {'id': 'services', 'title': 'Servicios'},
            {'id': 'sales', 'title': 'Venta comercial'},
            {'id': 'promotions', 'title': 'Promociones'},
            {'id': 'faq', 'title': 'Preguntas frecuentes'},
            {'id': 'contact', 'title': 'Contactar agente'}
        ]
        state['step'] = 'main_menu'

    elif state['step'] == 'main_menu':
        if text == 'services':
            response = '🏥 ¡Bienvenido a la Clínica San José! Estamos aquí para cuidar de ti. ¿Deseas agendar una cita o regresar al menú?'
            buttons = [
                {'id': 'schedule_appointment', 'title': 'Agendar cita'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'services_menu'
        elif text == 'sales':
            response = '🛍️ ¡Bienvenido a la simulación de Ventas! Selecciona un producto o regresa al menú.'
            buttons = [
                {'id': 'iphone', 'title': 'Iphone 17 Pro Max'},
                {'id': 'dior', 'title': 'Dior Perfume'},
                {'id': 'nike', 'title': 'Zapatillas Nike'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'sales_menu'
        elif text == 'promotions':
            response = '🎉 ¡Descubre nuestras promociones exclusivas! Ahorra hasta un 20% en productos seleccionados esta semana. ¿Quieres conocer las ofertas o regresar al menú?'
            buttons = [
                {'id': 'view_offers', 'title': 'Ver ofertas'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'promotions_menu'
        elif text == 'faq':
            response = '❓ ¡Preguntas frecuentes! Puedes preguntar: "¿Cuáles son los horarios?", "¿Cómo compro un producto?", "¿Cómo agendo una cita?" o "¿Cuáles son las promociones?". Escribe tu pregunta o regresa al menú.'
            buttons = [
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'faq_menu'
        elif text == 'contact':
            response = '🟢 Conectando con un agente... ¡Estás en modo LIVE con Enzo! Escribe tu mensaje y te responderemos pronto.'
            buttons = [
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'contact_agent'
            emit('update_title', {'title': 'LIVE 🟢 Enzo'})
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]

    elif state['step'] == 'services_menu':
        if text == 'schedule_appointment':
            response = '📅 Elige un horario para tu cita en la Clínica San José:'
            buttons = schedules + [{'id': 'main_menu', 'title': 'Regresar al menú'}]
            state['step'] = 'schedule_selection'
        elif text == 'main_menu':
            response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]
            state['step'] = 'main_menu'
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = [
                {'id': 'schedule_appointment', 'title': 'Agendar cita'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]

    elif state['step'] == 'sales_menu':
        if text in [p['id'] for p in products]:
            product = next(p for p in products if p['id'] == text)
            response = f'Has seleccionado {product["title"]}. ¿Qué deseas hacer?'
            buttons = [
                {'id': f'buy_{text}', 'title': 'Comprar'},
                {'id': f'info_{text}', 'title': 'Más información'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'product_details'
            state['last_product'] = text
        elif text == 'main_menu':
            response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]
            state['step'] = 'main_menu'
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = [
                {'id': 'iphone', 'title': 'Iphone 17 Pro Max'},
                {'id': 'dior', 'title': 'Dior Perfume'},
                {'id': 'nike', 'title': 'Zapatillas Nike'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]

    elif state['step'] == 'product_details':
        if text.startswith('buy_'):
            product_id = text.replace('buy_', '')
            product = next(p for p in products if p['id'] == product_id)
            response = f'¡Genial! Has elegido comprar {product["title"]}. Por favor, contáctanos para finalizar tu compra. ¿Algo más en lo que pueda ayudarte?'
            buttons = [
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'main_menu'
        elif text.startswith('info_'):
            product_id = text.replace('info_', '')
            product = next(p for p in products if p['id'] == product_id)
            if product_id == 'iphone':
                response = f'Más información sobre {product["title"]}: El iPhone 17 Pro Max cuenta con una pantalla OLED de 6.9", chip A19 Bionic, cámara de 48MP con zoom mejorado y batería de larga duración. ¿Qué deseas hacer?'
            elif product_id == 'dior':
                response = f'Más información sobre {product["title"]}: Dior Perfume es una fragancia elegante con notas de jazmín, rosa y vainilla, perfecta para cualquier ocasión. ¡Edición limitada! ¿Qué deseas hacer?'
            elif product_id == 'nike':
                response = f'Más información sobre {product["title"]}: Las Zapatillas Nike AirMax ofrecen máxima comodidad, diseño moderno y suela antideslizante para deportes y uso diario. ¿Qué deseas hacer?'
            buttons = [
                {'id': f'buy_{product_id}', 'title': 'Comprar'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'product_details'
        elif text == 'main_menu':
            response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]
            state['step'] = 'main_menu'
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = [
                {'id': f'buy_{state.get("last_product", "iphone")}', 'title': 'Comprar'},
                {'id': f'info_{state.get("last_product", "iphone")}', 'title': 'Más información'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]

    elif state['step'] == 'promotions_menu':
        if text == 'view_offers':
            response = '🔥 Ofertas especiales: 20% de descuento en iPhone 17 Pro Max, 15% en Dior Perfume y 10% en Zapatillas Nike. ¡Aprovecha antes de que termine la semana! ¿Qué deseas hacer?'
            buttons = [
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'main_menu'
        elif text == 'main_menu':
            response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]
            state['step'] = 'main_menu'
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = [
                {'id': 'view_offers', 'title': 'Ver ofertas'},
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]

    elif state['step'] == 'faq_menu':
        response = 'Esto es una demo, pero el siguiente en responder puedes ser tú! 😄 Escribe tu pregunta o regresa al menú.'
        buttons = [
            {'id': 'main_menu', 'title': 'Regresar al menú'}
        ]
        state['step'] = 'main_menu'

    elif state['step'] == 'contact_agent':
        response = 'Esto es una demo, pero el siguiente en responder puedes ser tú! 😄 Escribe tu mensaje o regresa al menú.'
        buttons = [
            {'id': 'main_menu', 'title': 'Regresar al menú'}
        ]
        state['step'] = 'main_menu'

    elif state['step'] == 'schedule_selection':
        if text in [s['id'] for s in schedules]:
            schedule = next(s for s in schedules if s['id'] == text)
            response = f'¡Cita agendada para {schedule["title"]}! ¿Algo más en lo que pueda ayudarte?'
            buttons = [
                {'id': 'main_menu', 'title': 'Regresar al menú'}
            ]
            state['step'] = 'main_menu'
        elif text == 'main_menu':
            response = f'¡Encantado, {state["name"].capitalize()}! ¿En qué puedo ayudarte hoy? 😄'
            buttons = [
                {'id': 'services', 'title': 'Servicios'},
                {'id': 'sales', 'title': 'Venta comercial'},
                {'id': 'promotions', 'title': 'Promociones'},
                {'id': 'faq', 'title': 'Preguntas frecuentes'},
                {'id': 'contact', 'title': 'Contactar agente'}
            ]
            state['step'] = 'main_menu'
        else:
            response = 'Por favor, selecciona una opción de los botones.'
            buttons = schedules + [{'id': 'main_menu', 'title': 'Regresar al menú'}]

    if response:
        print(f'📢 Enviando respuesta web: {{"response": "{response}", "buttons": {buttons}}}')
        emit('message', {'response': response, 'buttons': buttons})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5001)