from flask import Flask, render_template, jsonify
from threading import Thread, Lock
from core.packet_sniffer import IDSSniffer
import logging
import os

app = Flask(__name__, template_folder='templates')
alerts = []
alert_lock = Lock()  # Thread-safe alerts

# Ensure log directory exists
os.makedirs('logs', exist_ok=True)
logging.basicConfig(filename='logs/ids.log', level=logging.INFO)

class IDSDashboard:
    def __init__(self, interface):
        self.interface = interface
        self.sniffer = IDSSniffer(interface)
        self.sniffer_thread = Thread(target=self.sniffer.start_sniffing, daemon=True)
        
    def run(self):
        self.sniffer_thread.start()
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/alerts')
def get_alerts():
    try:
        with open('logs/ids.log') as f:
            alerts = [line.strip() for line in f if 'WARNING' in line]
        return jsonify(alerts[-20:])
    except Exception as e:
        logging.error(f"Alert error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    dashboard = IDSDashboard("eth0")  # Change to your interface
    dashboard.run()