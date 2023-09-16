import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import requests
import re
import hashlib
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet

class ThreatIntelligenceTool:
    def __init__(self):
        self.exploitdb_url = 'https://www.exploit-db.com/api/search'
        self.nist_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json'
        self.cve_url = 'https://cve.mitre.org/data/downloads/allitems-cvrf-year-2023.json'
        self.incidents = []
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

    def fetch_threat_data(self):
        self.incidents = []

        # Obtener datos de ExploitDB
        exploitdb_data = self.get_exploitdb_data()
        self.incidents.extend(exploitdb_data)

        # Obtener datos de NIST
        nist_data = self.get_nist_data()
        self.incidents.extend(nist_data)

        # Obtener datos de CVE MITRE
        cve_data = self.get_cve_data()
        self.incidents.extend(cve_data)

    def get_exploitdb_data(self):
        # Realizar consulta a la API de ExploitDB
        response = requests.get(self.exploitdb_url)
        if response.status_code == 200:
            exploitdb_data = response.json()
            return exploitdb_data
        else:
            print("Error al obtener datos de ExploitDB")
            return []

    def get_nist_data(self):
        # Realizar consulta a la API de NIST
        response = requests.get(self.nist_url)
        if response.status_code == 200:
            nist_data = response.json()
            return nist_data['CVE_Items']
        else:
            print("Error al obtener datos de NIST")
            return []

    def get_cve_data(self):
        # Realizar consulta a la API de CVE MITRE
        response = requests.get(self.cve_url)
        if response.status_code == 200:
            cve_data = response.json()
            return cve_data['CVE_Items']
        else:
            print("Error al obtener datos de CVE MITRE")
            return []

    def analyze_threat_advanced(self, selected_text):
        # Realizar un análisis más avanzado aquí
        analysis_result = "Resultados del análisis avanzado:\n"

        # Detección de números de tarjetas de crédito (ejemplo de patrón)
        credit_card_numbers = re.findall(r'\b(?:\d{4}[- ]?){3}\d{4}\b', selected_text)
        if credit_card_numbers:
            analysis_result += "- Números de Tarjetas de Crédito detectados:\n"
            for cc_number in credit_card_numbers:
                analysis_result += f"  - {cc_number}\n"

        # Detección de ransomware (ejemplo de patrón)
        ransomware_patterns = ['ransomware', 'cryptolocker', 'locky']
        for pattern in ransomware_patterns:
            if pattern in selected_text.lower():
                analysis_result += f"- Detección de posible ransomware: {pattern.capitalize()}\n"

        # Clasificación de amenazas (ejemplo de clasificación)
        threat_category = self.classify_threat(selected_text)
        analysis_result += f"- Categoría de amenaza: {threat_category}\n"

        # Agregar más análisis avanzado según sea necesario

        if analysis_result == "Resultados del análisis avanzado:\n":
            analysis_result += "- No se encontraron patrones ni indicios de amenazas significativas en el texto."

        return analysis_result

    def classify_threat(self, text):
        # Clasificar la amenaza en función del contenido del texto
        # Esta es una función de ejemplo y puede personalizarse según las necesidades específicas
        if 'malware' in text.lower():
            return "Malware"
        elif 'phishing' in text.lower():
            return "Phishing"
        elif 'ataque de fuerza bruta' in text.lower():
            return "Ataque de Fuerza Bruta"
        else:
            return "Desconocida"

    def respond_to_incident_advanced(self, selected_text):
        # Realizar una respuesta más avanzada a incidentes aquí
        response_result = "Acciones avanzadas de respuesta al incidente:\n"

        # Ejemplo de desconexión remota de dispositivos comprometidos
        remote_device_ip = simpledialog.askstring("Desconectar Dispositivo", "Introduce la IP del dispositivo a desconectar:")
        if remote_device_ip:
            response_result += f"- Desconectar remotamente el dispositivo con IP: {remote_device_ip}\n"
            self.disconnect_remote_device(remote_device_ip)

        # Ejemplo de cifrado de datos
        sensitive_data = self.detect_sensitive_data(selected_text)
        if sensitive_data:
            response_result += "- Cifrar datos sensibles\n"
            encrypted_data = self.encrypt_data(sensitive_data)
            response_result += f"- Datos cifrados: {encrypted_data}\n"

        # Registrar el incidente en un archivo de registro
        self.log_incident(selected_text)

        # Notificar a las autoridades (ejemplo)
        if 'grave' in selected_text.lower():
            response_result += "- Notificar a las autoridades\n"
            self.notify_authorities(selected_text)

        # Restaurar archivos o sistemas (ejemplo)
        if 'restaurar' in selected_text.lower():
            response_result += "- Restaurar archivos o sistemas comprometidos\n"

        # Agregar más acciones de respuesta avanzadas según sea necesario

        if response_result == "Acciones avanzadas de respuesta al incidente:\n":
            response_result += "- No se realizaron acciones de respuesta avanzadas en este incidente."

        return response_result

    def disconnect_remote_device(self, ip_address):
        # Implementar lógica para desconectar remotamente el dispositivo con la IP proporcionada
        # Esta es una función de ejemplo y debe configurarse para tu entorno específico
        print(f"Desconectando el dispositivo con IP: {ip_address}")

    def detect_sensitive_data(self, selected_text):
        # Implementar lógica para detectar datos sensibles en el texto
        # Esta es una función de ejemplo y puede personalizarse según las necesidades específicas
        sensitive_data = re.findall(r'SS[0-9]{2}-[0-9]{2}-[0-9]{4}', selected_text)
        if sensitive_data:
            return sensitive_data
        return None

    def encrypt_data(self, data):
        # Implementar lógica para cifrar datos utilizando Fernet
        # Esta función utiliza una clave generada al inicio de la aplicación
        encrypted_data = []
        for item in data:
            encrypted_item = self.fernet.encrypt(item.encode())
            encrypted_data.append(encrypted_item)
        return encrypted_data

    def log_incident(self, incident_text):
        # Implementar lógica para registrar el incidente en un archivo de registro
        # Esta es una función de ejemplo y debe configurarse para tu entorno específico
        with open('incident_log.txt', 'a') as log_file:
            log_file.write(f"Incidente registrado:\n{incident_text}\n\n")

    def notify_authorities(self, incident_text):
        # Implementar lógica para notificar a las autoridades en caso de amenazas graves
        # Esta es una función de ejemplo y debe configurarse para tu entorno específico
        email_subject = "Amenaza Grave Detectada"
        email_body = f"Se ha detectado una amenaza grave:\n\n{incident_text}\n\nTomar medidas inmediatas."
        self.send_email(email_subject, email_body)

    def send_email(self, subject, body):
        # Implementar lógica para enviar correos electrónicos
        # Esta es una función de ejemplo y debe configurarse para tu entorno específico
        smtp_server = 'smtp.example.com'
        smtp_port = 587
        sender_email = 'your_email@example.com'
        sender_password = 'your_password'
        recipient_email = 'recipient@example.com'

        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)

            message = MIMEMultipart()
            message['From'] = sender_email
            message['To'] = recipient_email
            message['Subject'] = subject

            message.attach(MIMEText(body, 'plain'))

            server.sendmail(sender_email, recipient_email, message.as_string())
            server.quit()
            print("Correo electrónico enviado con éxito")
        except Exception as e:
            print(f"Error al enviar el correo electrónico: {str(e)}")

class ThreatIntelligenceToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MSI Threat Intelligence & Blue Team Tool")
        self.root.geometry("800x600")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.threat_tab = tk.Frame(self.notebook)
        self.blue_team_tab = tk.Frame(self.notebook)

        self.notebook.add(self.threat_tab, text="Threat Intelligence")
        self.notebook.add(self.blue_team_tab, text="Blue Team")

        self.create_threat_tab()
        self.create_blue_team_tab()

    def create_threat_tab(self):
        # Crear la pestaña de Threat Intelligence
        self.threat_text = scrolledtext.ScrolledText(self.threat_tab, wrap=tk.WORD, width=40, height=10)
        self.threat_text.grid(column=0, row=0, padx=10, pady=10, sticky="nsew")

        fetch_button = ttk.Button(self.threat_tab, text="Obtener Amenazas", command=self.fetch_threat_data)
        fetch_button.grid(column=0, row=1, padx=10, pady=5, sticky="w")

        analyze_button = ttk.Button(self.threat_tab, text="Analizar Amenazas", command=self.analyze_threat)
        analyze_button.grid(column=0, row=1, padx=120, pady=5, sticky="w")

    def create_blue_team_tab(self):
        # Crear la pestaña de Blue Team
        self.blue_team_text = scrolledtext.ScrolledText(self.blue_team_tab, wrap=tk.WORD, width=40, height=10)
        self.blue_team_text.grid(column=0, row=0, padx=10, pady=10, sticky="nsew")

        response_button = ttk.Button(self.blue_team_tab, text="Responder a Incidente", command=self.respond_to_incident)
        response_button.grid(column=0, row=1, padx=10, pady=5, sticky="w")

        encrypt_button = ttk.Button(self.blue_team_tab, text="Encriptar Datos", command=self.encrypt_data)
        encrypt_button.grid(column=0, row=1, padx=200, pady=5, sticky="w")

    def fetch_threat_data(self):
        threat_tool.fetch_threat_data()
        self.threat_text.delete(1.0, tk.END)
        self.threat_text.insert(tk.END, "Datos de amenazas obtenidos:\n")
        for incident in threat_tool.incidents:
            self.threat_text.insert(tk.END, f"- {incident['title']}\n")
            self.threat_text.insert(tk.END, f"  Descripción: {incident['description']}\n")
            self.threat_text.insert(tk.END, f"  Fecha de Publicación: {incident['published']}\n\n")

    def analyze_threat(self):
        selected_text = self.threat_text.get("1.0", tk.END)
        analysis_result = threat_tool.analyze_threat_advanced(selected_text)
        self.threat_text.insert(tk.END, analysis_result)

    def respond_to_incident(self):
        selected_text = self.blue_team_text.get("1.0", tk.END)
        response_result = threat_tool.respond_to_incident_advanced(selected_text)
        self.blue_team_text.insert(tk.END, response_result)

    def encrypt_data(self):
        data_to_encrypt = simpledialog.askstring("Encriptar Datos", "Introduce los datos a encriptar:")
        if data_to_encrypt:
            encrypted_data = threat_tool.encrypt_data([data_to_encrypt])
            self.blue_team_text.insert(tk.END, f"Datos Encriptados: {encrypted_data}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatIntelligenceToolApp(root)
    app.root.protocol("WM_DELETE_WINDOW", lambda: exit_app(root))  # Manejar cierre de ventana
    threat_tool = ThreatIntelligenceTool()
    app.root.mainloop()

# Función para mostrar disclaimer y salir de la aplicación
def exit_app(root):
    disclaimer = "Descargo de responsabilidad:\n\n" \
                "Este programa es una herramienta de seguridad destinada a uso educativo y de investigación.\n" \
                "El uso de esta herramienta con fines comerciales está prohibido sin el permiso del creador.\n\n" \
                "¿Está seguro de que desea salir de la aplicación?"
    confirm_exit = messagebox.askyesno("Salir de la aplicación", disclaimer)
    if confirm_exit:
        root.destroy()
