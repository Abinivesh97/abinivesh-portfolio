import tkinter as tk
from tkinter import scrolledtext
import threading
import platform
import os
import socket
from scapy.all import IP, ICMP, UDP, TCP, DNS, DNSQR, send, Raw, fragment

class ScapyLabApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scapy Network Lab")
        self.root.geometry("500x800")
        self.root.configure(bg="#0b1220")

        # Title
        title = tk.Label(root, text="End-to-End Traffic Generator", font=("Inter", 16, "bold"), bg="#0b1220", fg="#34d399")
        title.pack(pady=(15, 5))

        # Target IP Input Frame
        ip_frame = tk.Frame(root, bg="#0b1220")
        ip_frame.pack(pady=5)
        tk.Label(ip_frame, text="Target IP:", font=("Inter", 10, "bold"), bg="#0b1220", fg="#94a3b8").pack(side="left", padx=5)
        self.ip_entry = tk.Entry(ip_frame, font=("Consolas", 12), bg="#1e293b", fg="#ffffff", width=15, justify="center")
        self.ip_entry.insert(0, "93.184.216.34") # Default: example.com (Change to 127.0.0.1 to test locally)
        self.ip_entry.pack(side="left")

        # Scrolling Status Log
        self.log_box = scrolledtext.ScrolledText(root, height=8, font=("Consolas", 9), bg="#0f1830", fg="#60a5fa", wrap="word")
        self.log_box.pack(pady=10, padx=20, fill="x")
        self.log("System Ready. Run as Admin/Root to forge packets.")

        # Listener Toggle
        self.listening = False
        self.listen_btn = tk.Button(root, text="Start Local UDP Listener (Port 55555)", font=("Inter", 10, "bold"), 
                                    bg="#064e3b", fg="#ffffff", activebackground="#047857", activeforeground="#ffffff", 
                                    command=self.toggle_listener)
        self.listen_btn.pack(pady=(0, 10), fill="x", padx=40, ipady=4)

        # Buttons (Sender)
        self.create_button("1. Forge Ping (ICMP)", self.forge_icmp, "#f59e0b")
        self.create_button("2. Forge DNS Query (UDP)", self.forge_dns, "#a78bfa")
        self.create_button("3. Forge HTTP GET (TCP 80)", self.forge_http, "#60a5fa")
        self.create_button("4. Forge TLS Handshake (TCP 443)", self.forge_tls, "#34d399")
        self.create_button("5. Custom Encapsulation (UDP)", self.forge_custom_udp, "#f472b6")
        self.create_button("6. TCP Segmentation (Layer 4)", self.forge_tcp_segmentation, "#2dd4bf")
        self.create_button("7. IP Fragmentation (Layer 3)", self.forge_ip_fragmentation, "#ef4444")

    def create_button(self, text, command, color):
        btn = tk.Button(self.root, text=text, font=("Inter", 11, "bold"), bg="#111b33", fg=color, 
                        activebackground="#1e293b", activeforeground=color, relief="ridge", borderwidth=2,
                        command=lambda: threading.Thread(target=command, daemon=True).start())
        btn.pack(pady=5, fill="x", padx=40, ipady=3)

    def log(self, message):
        # Safely insert into the tkinter text box from a thread
        self.root.after(0, self._append_log, message)

    def _append_log(self, message):
        self.log_box.insert(tk.END, f"> {message}\n")
        self.log_box.see(tk.END)

    # --- LISTENER MODULE ---
    def toggle_listener(self):
        if not self.listening:
            self.listening = True
            self.listen_btn.config(text="Stop Local UDP Listener", bg="#7f1d1d")
            threading.Thread(target=self.udp_listener_thread, daemon=True).start()
        else:
            self.listening = False
            self.listen_btn.config(text="Start Local UDP Listener (Port 55555)", bg="#064e3b")

    def udp_listener_thread(self):
        self.log("Listener active. Waiting for UDP packets on port 55555...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 55555))
            sock.settimeout(1.0)
            while self.listening:
                try:
                    data, addr = sock.recvfrom(2048)
                    self.log(f"[LISTENER] Caught packet from {addr[0]}: {data.decode('utf-8', errors='ignore')}")
                except socket.timeout:
                    continue
            sock.close()
            self.log("Listener shut down.")
        except Exception as e:
            self.log(f"Listener Error: {e}")
            self.listening = False

    # --- SENDER MODULES ---
    def forge_icmp(self):
        target = self.ip_entry.get()
        self.log(f"Forging ICMP Ping to {target}...")
        try:
            pkt = IP(dst=target) / ICMP()
            send(pkt, verbose=False)
            self.log("ICMP sent!")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_dns(self):
        self.log("Forging DNS query to 8.8.8.8...")
        try:
            pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
            send(pkt, verbose=False)
            self.log("DNS Query sent!")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_http(self):
        target = self.ip_entry.get()
        self.log(f"Forging raw HTTP GET to {target}...")
        try:
            http_payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            pkt = IP(dst=target) / TCP(dport=80, sport=54321, flags="PA") / Raw(load=http_payload)
            send(pkt, verbose=False)
            self.log("HTTP packet sent!")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_tls(self):
        target = self.ip_entry.get()
        self.log(f"Injecting TLS Client Hello to {target}...")
        try:
            # Hex dump of TLSv1.2 Client Hello
            client_hello = bytes.fromhex("16030100410100003d03030000000000000000000000000000000000000000000000000000000000000000000002002f010000120000000e000c0000096c6f63616c686f7374")
            pkt = IP(dst=target) / TCP(dport=443, sport=54322, flags="PA") / Raw(load=client_hello)
            send(pkt, verbose=False)
            self.log("TLS packet sent!")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_custom_udp(self):
        target = self.ip_entry.get()
        self.log(f"Forging encapsulated UDP payload to {target}...")
        try:
            secret_data = "=== ENCAPSULATION_PROVEN_IN_SCAPY ==="
            pkt = IP(dst=target) / UDP(dport=55555, sport=12345) / Raw(load=secret_data)
            send(pkt, verbose=False)
            self.log("Custom UDP sent!")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_tcp_segmentation(self):
        target = self.ip_entry.get()
        self.log(f"Simulating TCP Segmentation to {target}...")
        try:
            payload = b"X" * 4000
            chunk_size = 1400 # Smaller than MTU
            seq_num = 1000
            for i in range(0, len(payload), chunk_size):
                chunk = payload[i:i+chunk_size]
                pkt = IP(dst=target) / TCP(dport=80, sport=55555, seq=seq_num, flags="A") / Raw(load=chunk)
                send(pkt, verbose=False)
                seq_num += len(chunk)
            self.log("TCP Segments sent! Wireshark will show TCP slicing.")
        except Exception as e:
            self.log(f"Error: {e}")

    def forge_ip_fragmentation(self):
        target = self.ip_entry.get()
        self.log(f"Forging IP Fragmentation to {target}...")
        try:
            # 1. We make an oversized ICMP packet (4000 bytes)
            payload = b"F" * 4000
            pkt = IP(dst=target) / ICMP() / Raw(load=payload)
            
            # 2. We explicitly tell Scapy to fragment it at Layer 3
            frags = fragment(pkt, fragsize=1400)
            
            for f in frags:
                send(f, verbose=False)
                
            self.log(f"Sent {len(frags)} IP fragments! Look for 'IPv4 Fragment' in Wireshark.")
        except Exception as e:
            self.log(f"Error: {e}")

if __name__ == "__main__":
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    root = tk.Tk()
    app = ScapyLabApp(root)
    if not is_admin:
        app.log("WARNING: Not running as Admin! Packet injection will fail.")
    root.mainloop()