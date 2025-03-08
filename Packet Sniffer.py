import tkinter as tk
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("700x500")

frame = tk.Frame(root)
frame.pack(pady=10)

text_area = tk.Text(frame, wrap=tk.WORD, height=20, width=80, state=tk.DISABLED)
text_area.pack(side=tk.LEFT)

scrollbar = tk.Scrollbar(frame, command=text_area.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_area.config(yscrollcommand=scrollbar.set)

sniffing = False
sniff_thread = None

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
        else:
            src_port = "N/A"
            dst_port = "N/A"
            proto_name = "Other"

        packet_info = f"[+] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {proto_name}\n"

        if packet.haslayer(Raw):
            packet_info += f"    Data: {packet[Raw].load[:50]}\n"

        text_area.config(state=tk.NORMAL)
        text_area.insert(tk.END, packet_info)
        text_area.see(tk.END)
        text_area.config(state=tk.DISABLED)

def start_sniffing():
    global sniffing, sniff_thread
    if not sniffing:
        sniffing = True
        text_area.config(state=tk.NORMAL)
        text_area.insert(tk.END, "[*] Starting Packet Sniffer...\n")
        text_area.config(state=tk.DISABLED)
        sniff_thread = threading.Thread(target=sniff, kwargs={"prn": packet_handler, "store": False, "stop_filter": lambda _: not sniffing}, daemon=True)
        sniff_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, "[*] Stopping Packet Sniffer...\n")
    text_area.config(state=tk.DISABLED)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(side=tk.RIGHT, padx=5)

root.mainloop()
