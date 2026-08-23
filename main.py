# Importación de módulos necesarios
import customtkinter as ctk  # Módulo para crear la interfaz gráfica personalizada
from packet_analyzer import PacketAnalyzer  # Módulo personalizado para analizar paquetes
from scapy.all import *  # Módulo para captura y análisis de paquetes de red
from threading import Thread  # Módulo para manejo de hilos
import time  # Módulo para funciones relacionadas con el tiempo

class NetworkAnalyzerGUI(ctk.CTk):
    """Interfaz gráfica principal para el analizador de red"""
    
    def __init__(self):
        """Inicializa la interfaz gráfica y configura todos los componentes visuales"""
        super().__init__()  # Inicializa la clase padre CTk

        # Configuración básica de la ventana
        self.title("Analizador de Red")  # Establece el título de la ventana
        self.geometry("1200x800")  # Establece el tamaño de la ventana
        ctk.set_appearance_mode("dark")  # Establece el modo oscuro para la interfaz

        # Inicialización de variables de control
        self.packet_analyzer = PacketAnalyzer()  # Instancia del analizador de paquetes
        self.capture_thread = None  # Variable para el hilo de captura
        self.is_capturing = False  # Bandera para controlar la captura normal
        self.is_unique_capturing = False  # Bandera para controlar la captura única

        # Creación del frame principal
        self.main_frame = ctk.CTkFrame(self)  # Frame contenedor principal
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Frame para los controles
        self.control_frame = ctk.CTkFrame(self.main_frame)  # Frame para botones y controles
        self.control_frame.pack(fill="x", padx=5, pady=5)

        # Configuración de botones de control
        self.start_button = ctk.CTkButton(self.control_frame, text="Iniciar Captura", command=self.toggle_capture)
        self.start_button.pack(side="left", padx=5)

        self.unique_capture_button = ctk.CTkButton(self.control_frame, text="Captura Única", command=self.toggle_unique_capture)
        self.unique_capture_button.pack(side="left", padx=5)

        self.clear_button = ctk.CTkButton(self.control_frame, text="Limpiar", command=self.clear_packets)
        self.clear_button.pack(side="left", padx=5)

        # Configuración del campo de búsqueda
        self.search_frame = ctk.CTkFrame(self.control_frame)  # Frame para elementos de búsqueda
        self.search_frame.pack(side="right", padx=5)
        
        self.search_label = ctk.CTkLabel(self.search_frame, text="Buscar paquete #:")
        self.search_label.pack(side="left", padx=5)
        
        self.search_entry = ctk.CTkEntry(self.search_frame)  # Campo de entrada para búsqueda
        self.search_entry.pack(side="left", padx=5)
        
        self.search_button = ctk.CTkButton(self.search_frame, text="Buscar", command=self.search_packet)
        self.search_button.pack(side="left", padx=5)

        # Configuración del frame para la tabla de paquetes
        self.table_frame = ctk.CTkFrame(self.main_frame)  # Frame para la tabla de paquetes
        self.table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Configuración de encabezados de la tabla
        self.headers = ["No.", "Tiempo", "Protocolo", "Origen", "Destino", "Longitud", "Info"]
        self.header_frame = ctk.CTkFrame(self.table_frame)
        self.header_frame.pack(fill="x", padx=5, pady=5)

        # Creación de las etiquetas de encabezado
        for i, header in enumerate(self.headers):
            width = 100 if header in ["No.", "Tiempo", "Protocolo", "Longitud"] else 200
            label = ctk.CTkLabel(self.header_frame, text=header, width=width)
            label.grid(row=0, column=i, padx=2)

        # Configuración del área scrollable para los paquetes
        self.scroll_frame = ctk.CTkScrollableFrame(self.table_frame)
        self.scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Lista para almacenar las filas de la tabla
        self.table_rows = []

    def toggle_capture(self):
        """Alterna entre iniciar y detener la captura normal de paquetes"""
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def toggle_unique_capture(self):
        """Alterna entre iniciar y detener la captura única de paquetes por protocolo"""
        if not self.is_unique_capturing:
            self.start_unique_capture()
        else:
            self.stop_unique_capture()

    def capture_unique_packets(self):
        """Inicia la captura de paquetes únicos por protocolo utilizando Scapy"""
        def packet_callback(packet):
            if self.is_unique_capturing:
                packet_info = self.packet_analyzer.capture_unique_protocol_packet(packet)
                if packet_info:
                    self.after(10, lambda: self.add_packet_to_table(packet_info))

        sniff(prn=packet_callback, store=False)  # Inicia la captura de paquetes

    def update_button_states(self):
        """Actualiza el estado de los botones según el estado actual de la captura"""
        if self.is_capturing:
            # Configuración de botones durante la captura normal
            self.start_button.configure(state="normal")
            self.unique_capture_button.configure(state="disabled")
            self.clear_button.configure(state="disabled")
            self.search_button.configure(state="disabled")
            self.search_entry.configure(state="disabled")
        elif self.is_unique_capturing:
            # Configuración de botones durante la captura única
            self.start_button.configure(state="disabled")
            self.unique_capture_button.configure(state="normal")
            self.clear_button.configure(state="disabled")
            self.search_button.configure(state="disabled")
            self.search_entry.configure(state="disabled")
        else:
            # Configuración de botones cuando no hay captura activa
            self.start_button.configure(state="normal")
            self.unique_capture_button.configure(state="normal")
            has_packets = len(self.table_rows) > 0
            self.clear_button.configure(state="normal" if has_packets else "disabled")
            self.search_button.configure(state="normal" if has_packets else "disabled")
            self.search_entry.configure(state="normal" if has_packets else "disabled")

    def start_capture(self):
        """Inicia la captura normal de paquetes en un hilo separado"""
        self.is_capturing = True  # Activa la bandera de captura
        self.start_button.configure(text="Detener Captura")
        self.update_button_states()
        self.capture_thread = Thread(target=self.capture_packets)
        self.capture_thread.daemon = True  # El hilo se cerrará cuando el programa principal termine
        self.capture_thread.start()

    def stop_capture(self):
        """Detiene la captura normal de paquetes"""
        self.is_capturing = False  # Desactiva la bandera de captura
        self.start_button.configure(text="Iniciar Captura")
        self.update_button_states()

    def start_unique_capture(self):
        """Inicia la captura única de paquetes en un hilo separado"""
        self.is_unique_capturing = True  # Activa la bandera de captura única
        self.unique_capture_button.configure(text="Detener Captura Única")
        self.update_button_states()
        self.capture_thread = Thread(target=self.capture_unique_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_unique_capture(self):
        """Detiene la captura única de paquetes"""
        self.is_unique_capturing = False  # Desactiva la bandera de captura única
        self.unique_capture_button.configure(text="Captura Única")
        self.update_button_states()

    def clear_packets(self):
        """Limpia todos los paquetes capturados de la tabla"""
        for row in self.table_rows:
            row.destroy()  # Elimina cada fila de la interfaz
        self.table_rows.clear()  # Limpia la lista de filas
        self.packet_analyzer = PacketAnalyzer()  # Reinicia el analizador
        self.update_button_states()

    def add_packet_to_table(self, packet_info):
        """Añade un nuevo paquete a la tabla de visualización"""
        row = len(self.table_rows)
        row_frame = ctk.CTkFrame(self.scroll_frame)
        row_frame.pack(fill="x", padx=2, pady=1)
        row_frame.bind("<Button-1>", lambda e, p=packet_info: self.show_packet_details(p))

        # Formatea el tiempo para mostrar minutos y segundos
        minutos = int(packet_info['time']) // 60
        segundos = packet_info['time'] % 60
        tiempo_formateado = f"{minutos:02d}:{segundos:06.3f}"

        # Añade cada campo del paquete a la tabla
        ctk.CTkLabel(row_frame, text=str(packet_info['index']), width=100).grid(row=0, column=0, padx=2)
        ctk.CTkLabel(row_frame, text=tiempo_formateado, width=100).grid(row=0, column=1, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['protocol'], width=100).grid(row=0, column=2, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['source'], width=200).grid(row=0, column=3, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['destination'], width=200).grid(row=0, column=4, padx=2)
        ctk.CTkLabel(row_frame, text=str(packet_info['length']), width=100).grid(row=0, column=5, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['info'], width=200).grid(row=0, column=6, padx=2)

        self.table_rows.append(row_frame)
        self.update_button_states()

    def show_packet_details(self, packet_info):
        """Muestra una ventana con los detalles completos de un paquete"""
        details_window = ctk.CTkToplevel(self)  # Crea una ventana emergente
        details_window.title(f"Detalles del Paquete #{self.search_entry.get() if self.search_entry.get() else packet_info['index']}")
        details_window.geometry("600x400")

        # Crea un frame scrollable para los detalles
        details_frame = ctk.CTkScrollableFrame(details_window)
        details_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Muestra cada campo del paquete
        row = 0
        for key, value in packet_info.items():
            if key != 'time':  # Excluye el tiempo raw para mejor visualización
                label = ctk.CTkLabel(details_frame, text=f"{key}:", anchor="w")
                label.grid(row=row, column=0, padx=5, pady=2, sticky="w")
                
                # Maneja el caso especial del índice durante la búsqueda
                if key == 'index' and self.search_entry.get():
                    value = self.search_entry.get()
                    
                value_label = ctk.CTkLabel(details_frame, text=str(value), anchor="w")
                value_label.grid(row=row, column=1, padx=5, pady=2, sticky="w")
                row += 1

    def search_packet(self):
        """Busca un paquete específico por su número de índice"""
        try:
            index = int(self.search_entry.get())
            # Busca el paquete en ambas colecciones
            packet_info = self.packet_analyzer.get_packet(index)
            if not packet_info:
                packet_info = self.packet_analyzer.get_unique_packet(index)
            
            if packet_info:
                self.show_packet_details(packet_info)
            else:
                self.show_error("Paquete no encontrado")
        except ValueError:
            self.show_error("Por favor, ingrese un número válido")

    def show_error(self, message):
        """Muestra una ventana de error con un mensaje específico"""
        error_window = ctk.CTkToplevel(self)
        error_window.title("Error")
        error_window.geometry("300x100")
        ctk.CTkLabel(error_window, text=message).pack(padx=20, pady=20)

    def capture_packets(self):
        """Inicia la captura continua de paquetes utilizando Scapy"""
        def packet_callback(packet):
            if self.is_capturing:
                packet_info = self.packet_analyzer.capture_packet(packet)
                if packet_info['index'] < 30:  # Limita la captura a 30 paquetes
                    self.after(10, lambda: self.add_packet_to_table(packet_info))

        sniff(prn=packet_callback, store=False)  # Inicia la captura de paquetes

# Punto de entrada del programa
if __name__ == "__main__":
    app = NetworkAnalyzerGUI()  # Crea la instancia de la aplicación
    app.mainloop()  # Inicia el bucle principal de la aplicación