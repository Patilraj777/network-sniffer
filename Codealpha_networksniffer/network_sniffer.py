# Network Sniffer - Hacker Style GUI
# Author: RAJ Patil

import threading
from datetime import datetime
import socket
from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

sniffing = False
packet_count = {"Total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
packet_data = []
LOG_FILE = "packet_log.txt"

# -------------------- Packet Handling --------------------
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def log_packet(info):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(info + "\n")

def analyze_packet(packet):
    if not sniffing or not IP in packet:
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "Other")

    packet_count["Total"] += 1
    packet_count[protocol_name] = packet_count.get(protocol_name, 0) + 1

    log = f"[Time] {timestamp}"
    log += f"\n[Source IP]      : {src_ip} ({resolve_hostname(src_ip)})"
    log += f"\n[Destination IP] : {dst_ip} ({resolve_hostname(dst_ip)})"
    log += f"\n[Protocol]       : {protocol_name}"

    src_port = dst_port = ""
    if protocol_name == "TCP" and TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif protocol_name == "UDP" and UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if src_port and dst_port:
        log += f"\n[Src Port]       : {src_port}"
        log += f"\n[Dst Port]       : {dst_port}"

    log += "\n" + "-" * 70
    gui_output(log)
    log_packet(log)
    packet_data.append((timestamp, src_ip, dst_ip, protocol_name, src_port, dst_port))
    update_table()

# -------------------- Sniffer Control --------------------
def start_sniffing():
    global sniffing
    if sniffing:
        return
    sniffing = True
    thread = threading.Thread(target=sniff, kwargs={"filter": "ip", "prn": analyze_packet, "store": False})
    thread.daemon = True
    thread.start()
    gui_output("[INFO] Sniffing started...")
    status_label.config(text="Status: Sniffing...", fg="#00ff00")

def stop_sniffing():
    global sniffing
    sniffing = False
    gui_output("[INFO] Sniffing stopped.")
    status_label.config(text="Status: Stopped", fg="#ff4444")

def clear_output():
    output_text.config(state=tk.NORMAL)
    output_text.delete("1.0", tk.END)
    output_text.config(state=tk.DISABLED)
    for key in packet_count:
        packet_count[key] = 0
    packet_data.clear()
    for item in packet_table.get_children():
        packet_table.delete(item)
    status_label.config(text="Status: Ready", fg="#888888")

def export_log():
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file:
        with open(file, "w", encoding="utf-8") as f:
            for row in packet_data:
                f.write(" | ".join(map(str, row)) + "\n")
        gui_output(f"[INFO] Log exported to {file}")

def gui_output(text):
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, text + "\n")
    output_text.see(tk.END)
    output_text.config(state=tk.DISABLED)

def update_table():
    last_packet = packet_data[-1]
    packet_table.insert("", tk.END, values=last_packet)

def on_close():
    stop_sniffing()
    root.destroy()

# -------------------- GUI Setup --------------------
root = tk.Tk()
root.title("Network Sniffer")
root.geometry("1200x800")
root.configure(bg="#000000")
root.protocol("WM_DELETE_WINDOW", on_close)

# -------------------- Title --------------------
title = tk.Label(root, text="NETWORK SNIFFER", font=("Consolas", 26, "bold"), fg="#00ff88", bg="#000000")
title.pack(pady=10)

# -------------------- Buttons --------------------
button_frame = tk.Frame(root, bg="#000000")
button_frame.pack(pady=10)

btn_style = {"font": ("Consolas", 12, "bold"), "width": 14, "padx": 6, "pady": 6, "bd": 0, "cursor": "hand2"}

start_btn = tk.Button(button_frame, text="START", command=start_sniffing, bg="#1f7a1f", fg="white", activebackground="#2ecc71", **btn_style)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(button_frame, text="STOP", command=stop_sniffing, bg="#c0392b", fg="white", activebackground="#e74c3c", **btn_style)
stop_btn.pack(side=tk.LEFT, padx=10)

clear_btn = tk.Button(button_frame, text="CLEAR", command=clear_output, bg="#607d8b", fg="white", activebackground="#78909c", **btn_style)
clear_btn.pack(side=tk.LEFT, padx=10)

export_btn = tk.Button(button_frame, text="EXPORT LOG", command=export_log, bg="#0277bd", fg="white", activebackground="#039be5", **btn_style)
export_btn.pack(side=tk.LEFT, padx=10)

# -------------------- Packet Table --------------------
packet_table = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port"), show="headings", height=12)
for col in packet_table["columns"]:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=150)
packet_table.pack(padx=20, pady=10, fill=tk.X)

# -------------------- Console Output --------------------
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=150, height=12, state=tk.DISABLED, bg="#101010", fg="#00ff00", font=("Consolas", 11), insertbackground="#00ff00")
output_text.pack(padx=20, pady=10)

# -------------------- Status Bar --------------------
status_label = tk.Label(root, text="Status: Ready", font=("Consolas", 11, "bold"), bg="#000000", fg="#888888", anchor="w")
status_label.pack(fill=tk.X, padx=20, pady=5)

# -------------------- Launch --------------------
gui_output("[READY] Click 'START' to begin packet capture.")
root.mainloop()
