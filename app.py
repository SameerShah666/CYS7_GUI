import customtkinter as ctk
import threading
from scapy.all import sniff, IP, TCP, ICMP, wrpcap, rdpcap
from scapy.layers.inet import sr1
import random
from scapy.sendrecv import send
from tkinter import filedialog
import os


# hi
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PacketSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CYS7 Sniffing & Scanning Application")
        self.geometry("840x460")
        self.resizable(False, False)
        self.iconbitmap("icon.ico")

        self.sniffing = False
        self.filter = ""
        self.sniffed_packets = []
        self.port_scan_results = ""

        self.create_sidebar()
        self.create_display_area()

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="ns")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        # Title label
        title_label = ctk.CTkLabel(self.sidebar_frame, text="CYS7 Tool", font=("Arial", 24))
        title_label.grid(row=0, column=0, padx=20, pady=20)

        # Sniffing button
        self.sniff_button = ctk.CTkButton(self.sidebar_frame, text="Start Sniffing Packets", command=self.toggle_sniffing)
        self.sniff_button.grid(row=1, column=0, padx=20, pady=10)

        # Filter input field
        self.filter_label = ctk.CTkLabel(self.sidebar_frame, text="Packet Filter (optional):")
        self.filter_label.grid(row=2, column=0, padx=20, pady=5)
        self.filter_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="e.g., tcp, udp, ip src 192.168.1.1")
        self.filter_entry.grid(row=3, column=0, padx=20, pady=5)

        # Port Scanning button
        self.scan_button = ctk.CTkButton(self.sidebar_frame, text="Start Port Scanning", command=self.start_port_scan)
        self.scan_button.grid(row=4, column=0, padx=20, pady=10)

        # Save Sniffed Packets button
        self.save_button = ctk.CTkButton(self.sidebar_frame, text="Save Sniffed Packets", command=self.save_packets)
        self.save_button.grid(row=5, column=0, padx=20, pady=10)

        # Load Sniffed Packets button
        self.load_button = ctk.CTkButton(self.sidebar_frame, text="Load Sniffed Packets", command=self.load_packets)
        self.load_button.grid(row=6, column=0, padx=20, pady=10)

        # Exit button
        exit_button = ctk.CTkButton(self.sidebar_frame, text="Exit", command=self.quit, fg_color="#DC143C")
        exit_button.grid(row=7, column=0, padx=20, pady=10)

    def create_display_area(self):
        # Create main display area frame
        self.display_frame = ctk.CTkFrame(self, width=600)
        self.display_frame.grid(row=0, column=1, sticky="nsew",padx=10,pady=10)
        self.display_frame.grid_rowconfigure(0, weight=1)
        self.display_frame.grid_columnconfigure(0, weight=1)

        # Text area to display output
        self.output_text = ctk.CTkTextbox(self.display_frame, width=600, height=400)
        self.output_text.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def toggle_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.filter = self.filter_entry.get()
            self.sniff_button.configure(text="Stop Sniffing Packets")
            self.output_text.insert("end", f"Packet sniffing started with filter: {self.filter}\n")
            threading.Thread(target=self.sniff_packets).start()
        else:
            self.sniffing = False
            self.sniff_button.configure(text="Start Sniffing Packets")
            self.output_text.insert("end", "Packet sniffing stopped.\n")

    def sniff_packets(self):
        def process_packet(packet):
            if IP in packet:
                # Add packet to the list of sniffed packets
                self.sniffed_packets.append(packet)

                # Get detailed packet information
                pkt_info = (
                    f"Packet: {packet[IP].src} -> {packet[IP].dst} | "
                    f"Protocol: {packet[IP].proto} | "
                    f"Length: {len(packet)}\n"
                )
                self.output_text.insert("end", pkt_info)

        # Sniff packets based on user-specified filter
        sniff(prn=process_packet, filter=self.filter, store=False, stop_filter=lambda _: not self.sniffing)

    def start_port_scan(self):
        target_ip = ctk.CTkInputDialog(text="Enter target IP for port scanning:", title="Port Scanning").get_input()
        if target_ip:
            self.output_text.insert("end", f"Starting port scan on {target_ip}...\n")
            threading.Thread(target=self.port_scan, args=(target_ip,)).start()

    def port_scan(self, host):
        port_range = [22, 23, 80, 443]  # Example ports
        results = []
        for dst_port in port_range:
            src_port = random.randint(1025, 65534)
            resp = sr1(IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1, verbose=0)
            if resp is None:
                results.append(f"{host}:{dst_port} is filtered (no response).")
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send(IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="R"), verbose=0)
                    results.append(f"{host}:{dst_port} is open.")
                elif resp.getlayer(TCP).flags == 0x14:
                    results.append(f"{host}:{dst_port} is closed.")
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    results.append(f"{host}:{dst_port} is filtered (ICMP unreachable).")

        # Output results in the text box
        self.port_scan_results = "\n".join(results)
        self.output_text.insert("end", self.port_scan_results + "\n")

    def save_packets(self):
        if self.sniffed_packets:
            file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if file_path:
                wrpcap(file_path, self.sniffed_packets)
                self.output_text.insert("end", f"Packets saved to {file_path}\n")
        else:
            self.output_text.insert("end", "No packets to save.\n")

    def load_packets(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path and os.path.exists(file_path):
            loaded_packets = rdpcap(file_path)
            self.output_text.insert("end", f"Loaded {len(loaded_packets)} packets from {file_path}\n")
            # Display the loaded packets
            for packet in loaded_packets:
                if IP in packet:
                    pkt_info = (
                        f"Loaded Packet: {packet[IP].src} -> {packet[IP].dst} | "
                        f"Protocol: {packet[IP].proto} | "
                        f"Length: {len(packet)}\n"
                    )
                    self.output_text.insert("end", pkt_info)

# Run the application
if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
