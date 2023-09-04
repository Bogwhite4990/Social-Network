from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, send, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('chat.html')


@socketio.on('message')
def handle_message(message):
    send(message, broadcast=True)


if __name__ == '__main__':
    socketio.run(app)



