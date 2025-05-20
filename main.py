import customtkinter as ctk
from packet_analyzer import PacketAnalyzer
from scapy.all import *
from threading import Thread
import time

class NetworkAnalyzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configuración de la ventana principal
        self.title("Analizador de Red")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")

        # Inicializar el analizador de paquetes
        self.packet_analyzer = PacketAnalyzer()
        self.capture_thread = None
        self.is_capturing = False

        # Crear el frame principal
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Frame para controles
        self.control_frame = ctk.CTkFrame(self.main_frame)
        self.control_frame.pack(fill="x", padx=5, pady=5)

        # Botones de control
        self.start_button = ctk.CTkButton(self.control_frame, text="Iniciar Captura", command=self.toggle_capture)
        self.start_button.pack(side="left", padx=5)

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
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        self.is_capturing = True
        self.start_button.configure(text="Detener Captura")
        self.capture_thread = Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.is_capturing = False
        self.start_button.configure(text="Iniciar Captura")

    def capture_packets(self):
        def packet_callback(packet):
            if self.is_capturing:
                packet_info = self.packet_analyzer.capture_packet(packet)
                if packet_info['index'] < 30:
                    self.after(10, lambda: self.add_packet_to_table(packet_info))

        sniff(prn=packet_callback, store=False)

    def add_packet_to_table(self, packet_info):
        row = len(self.table_rows)
        row_frame = ctk.CTkFrame(self.scroll_frame)
        row_frame.pack(fill="x", padx=2, pady=1)
        row_frame.bind("<Button-1>", lambda e, p=packet_info: self.show_packet_details(p))

        # Añadir datos del paquete
        ctk.CTkLabel(row_frame, text=str(packet_info['index']), width=100).grid(row=0, column=0, padx=2)
        ctk.CTkLabel(row_frame, text=f"{packet_info['time']:.6f}", width=100).grid(row=0, column=1, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['protocol'], width=100).grid(row=0, column=2, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['source'], width=200).grid(row=0, column=3, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['destination'], width=200).grid(row=0, column=4, padx=2)
        ctk.CTkLabel(row_frame, text=str(packet_info['length']), width=100).grid(row=0, column=5, padx=2)
        ctk.CTkLabel(row_frame, text=packet_info['info'], width=200).grid(row=0, column=6, padx=2)

        self.table_rows.append(row_frame)

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
            packet_info = self.packet_analyzer.get_packet(index)
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

    def clear_packets(self):
        for row in self.table_rows:
            row.destroy()
        self.table_rows.clear()
        self.packet_analyzer = PacketAnalyzer()  # Esto reiniciará current_index a 0

if __name__ == "__main__":
    app = NetworkAnalyzerGUI()
    app.mainloop()