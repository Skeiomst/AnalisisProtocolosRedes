import customtkinter as ctk
from packet_analyzer import PacketAnalyzer
from scapy.all import *
from threading import Thread
import time

class NetworkAnalyzerGUI(ctk.CTk):
    """Interfaz gráfica principal para el analizador de red"""
    
    def __init__(self):
        """Inicializa la interfaz gráfica y configura todos los componentes visuales"""
        super().__init__()

        self.title("Analizador de Red")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")

        self.packet_analyzer = PacketAnalyzer()
        self.capture_thread = None
        self.is_capturing = False
        self.is_unique_capturing = False

        # Frame principal
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Frame para controles
        self.control_frame = ctk.CTkFrame(self.main_frame)
        self.control_frame.pack(fill="x", padx=5, pady=5)

        # Botones de control
        self.start_button = ctk.CTkButton(self.control_frame, text="Iniciar Captura", command=self.toggle_capture)
        self.start_button.pack(side="left", padx=5)

        self.unique_capture_button = ctk.CTkButton(self.control_frame, text="Captura Única", command=self.toggle_unique_capture)
        self.unique_capture_button.pack(side="left", padx=5)

        self.clear_button = ctk.CTkButton(self.control_frame, text="Limpiar", command=self.clear_packets)
        self.clear_button.pack(side="left", padx=5)

        # Campo de búsqueda
        self.search_frame = ctk.CTkFrame(self.control_frame)
        self.search_frame.pack(side="right", padx=5)
        
        self.search_label = ctk.CTkLabel(self.search_frame, text="Buscar paquete #:")
        self.search_label.pack(side="left", padx=5)
        
        self.search_entry = ctk.CTkEntry(self.search_frame)
        self.search_entry.pack(side="left", padx=5)
        
        self.search_button = ctk.CTkButton(self.search_frame, text="Buscar", command=self.search_packet)
        self.search_button.pack(side="left", padx=5)

        # Frame para la tabla de paquetes
        self.table_frame = ctk.CTkFrame(self.main_frame)
        self.table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Crear encabezados de la tabla
        self.headers = ["No.", "Tiempo", "Protocolo", "Origen", "Destino", "Longitud", "Info"]
        self.header_frame = ctk.CTkFrame(self.table_frame)
        self.header_frame.pack(fill="x", padx=5, pady=5)

        for i, header in enumerate(self.headers):
            width = 100 if header in ["No.", "Tiempo", "Protocolo", "Longitud"] else 200
            label = ctk.CTkLabel(self.header_frame, text=header, width=width)
            label.grid(row=0, column=i, padx=2)

        # Crear área de desplazamiento para los paquetes
        self.scroll_frame = ctk.CTkScrollableFrame(self.table_frame)
        self.scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Lista para mantener las filas de la tabla
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

        sniff(prn=packet_callback, store=False)

    def update_button_states(self):
        """Actualiza el estado de los botones según el estado actual de la captura"""
        if self.is_capturing:
            # Si está capturando normalmente
            self.start_button.configure(state="normal")
            self.unique_capture_button.configure(state="disabled")
            self.clear_button.configure(state="disabled")
            self.search_button.configure(state="disabled")
            self.search_entry.configure(state="disabled")
        elif self.is_unique_capturing:
            # Si está en captura única
            self.start_button.configure(state="disabled")
            self.unique_capture_button.configure(state="normal")
            self.clear_button.configure(state="disabled")
            self.search_button.configure(state="disabled")
            self.search_entry.configure(state="disabled")
        else:
            # Si no está capturando
            self.start_button.configure(state="normal")
            self.unique_capture_button.configure(state="normal")
            # Habilitar búsqueda y limpieza solo si hay paquetes
            has_packets = len(self.table_rows) > 0
            self.clear_button.configure(state="normal" if has_packets else "disabled")
            self.search_button.configure(state="normal" if has_packets else "disabled")
            self.search_entry.configure(state="normal" if has_packets else "disabled")

    def start_capture(self):
        """Inicia la captura normal de paquetes en un hilo separado"""
        self.is_capturing = True
        self.start_button.configure(text="Detener Captura")
        self.update_button_states()
        self.capture_thread = Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        """Detiene la captura normal de paquetes"""
        self.is_capturing = False
        self.start_button.configure(text="Iniciar Captura")
        self.update_button_states()

    def start_unique_capture(self):
        """Inicia la captura única de paquetes en un hilo separado"""
        self.is_unique_capturing = True
        self.unique_capture_button.configure(text="Detener Captura Única")
        self.update_button_states()
        self.capture_thread = Thread(target=self.capture_unique_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_unique_capture(self):
        """Detiene la captura única de paquetes"""
        self.is_unique_capturing = False
        self.unique_capture_button.configure(text="Captura Única")
        self.update_button_states()

    def clear_packets(self):
        for row in self.table_rows:
            row.destroy()
        self.table_rows.clear()
        self.packet_analyzer = PacketAnalyzer()
        self.update_button_states()

    def add_packet_to_table(self, packet_info):
        row = len(self.table_rows)
        row_frame = ctk.CTkFrame(self.scroll_frame)
        row_frame.pack(fill="x", padx=2, pady=1)
        row_frame.bind("<Button-1>", lambda e, p=packet_info: self.show_packet_details(p))

        # Formatear el tiempo
        minutos = int(packet_info['time']) // 60
        segundos = packet_info['time'] % 60
        tiempo_formateado = f"{minutos:02d}:{segundos:06.3f}"

        # Añadir datos del paquete
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
        # Crear ventana emergente para detalles
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"Detalles del Paquete #{self.search_entry.get() if self.search_entry.get() else packet_info['index']}")
        details_window.geometry("600x400")

        # Frame para los detalles
        details_frame = ctk.CTkScrollableFrame(details_window)
        details_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Mostrar todos los detalles disponibles
        row = 0
        for key, value in packet_info.items():
            if key != 'time':  # Excluir el tiempo para mejor visualización
                label = ctk.CTkLabel(details_frame, text=f"{key}:", anchor="w")
                label.grid(row=row, column=0, padx=5, pady=2, sticky="w")
                
                # Si es el índice y estamos buscando, usar el índice de búsqueda
                if key == 'index' and self.search_entry.get():
                    value = self.search_entry.get()
                    
                value_label = ctk.CTkLabel(details_frame, text=str(value), anchor="w")
                value_label.grid(row=row, column=1, padx=5, pady=2, sticky="w")
                row += 1

    def search_packet(self):
        try:
            index = int(self.search_entry.get())
            # Intentar obtener el paquete de ambas colecciones
            packet_info = self.packet_analyzer.get_packet(index)
            if not packet_info:
                # Si no se encuentra en la colección normal, buscar en la colección única
                packet_info = self.packet_analyzer.get_unique_packet(index)
            
            if packet_info:
                self.show_packet_details(packet_info)
            else:
                self.show_error("Paquete no encontrado")
        except ValueError:
            self.show_error("Por favor, ingrese un número válido")

    def show_error(self, message):
        error_window = ctk.CTkToplevel(self)
        error_window.title("Error")
        error_window.geometry("300x100")
        ctk.CTkLabel(error_window, text=message).pack(padx=20, pady=20)

    def capture_packets(self):
        """Inicia la captura continua de paquetes utilizando Scapy"""
        def packet_callback(packet):
            if self.is_capturing:
                packet_info = self.packet_analyzer.capture_packet(packet)
                if packet_info['index'] < 30:
                    self.after(10, lambda: self.add_packet_to_table(packet_info))

        sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    app = NetworkAnalyzerGUI()
    app.mainloop()