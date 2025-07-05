import threading
import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP
import csv
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation

# Initialize GUI
root = tk.Tk()
root.title("Real-time Network Traffic Monitor")

# Create frames for layout
top_frame = tk.Frame(root)
top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

bottom_frame = tk.Frame(root)
bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

# Create text widget to display all packets
text_widget = tk.Text(top_frame, wrap='word', height=20, width=40)
text_widget.pack(side=tk.LEFT, padx=5, pady=5)

# Create text widget to display filtered packets
filtered_text_widget = tk.Text(top_frame, wrap='word', height=20, width=40)
filtered_text_widget.pack(side=tk.LEFT, padx=5, pady=5)

# Create text widget to display high traffic packets
high_traffic_text_widget = tk.Text(top_frame, wrap='word', height=20, width=40)
high_traffic_text_widget.pack(side=tk.LEFT, padx=5, pady=5)

# Create a frame for the matplotlib figure
graph_frame = tk.Frame(root)
graph_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=False)

# Filter variables
protocol_filter = tk.StringVar(value="All")
src_ip_filter = tk.StringVar()
dst_ip_filter = tk.StringVar()
port_filter = tk.StringVar()

# List to store captured packets
captured_packets = []

# Counter to limit the number of displayed packets
packet_limit = 20
packet_count = 0

# Sniffing control variable
sniffing = threading.Event()

# List to store packet counts for visualization
packet_counts = []
time_elapsed = []

# List to store high traffic packets
high_traffic_packets = []

# Start time for calculating elapsed time
start_time = None

# Define a threshold for high traffic packets (e.g., 1000 bytes)
HIGH_TRAFFIC_THRESHOLD = 1000

# Define a callback function to process the packets
def packet_callback(packet):
    global packet_count, start_time
    if not sniffing.is_set():
        return

    try:
        if IP in packet:
            if start_time is None:
                start_time = datetime.now()  # Set start time when the first packet is captured

            current_time = datetime.now()
            elapsed_time = (current_time - start_time).total_seconds()
            
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            packet_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
            sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
            dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
            flags = packet[TCP].flags if TCP in packet else "N/A"
            ttl = packet[IP].ttl if IP in packet else "N/A"
            payload = packet[TCP].payload if TCP in packet else (packet[UDP].payload if UDP in packet else "N/A")
            size = len(packet)  # Packet size in bytes

            if proto == 6:  # TCP
                protocol = "TCP"
            elif proto == 17:  # UDP
                protocol = "UDP"
            else:
                protocol = "Other"

            # Check if the packet is high traffic
            high_traffic_label = "High Traffic" if size > HIGH_TRAFFIC_THRESHOLD else ""
            packet_info = (f"[{packet_time}] {protocol} Packet: {ip_src} -> {ip_dst} (Sport: {sport}, "
                           f"Dport: {dport}, Flags: {flags}, TTL: {ttl}, Size: {size} bytes) {high_traffic_label}\nPayload: {payload}\n\n")
            
            # Store packet information
            captured_packets.append((packet_time, protocol, ip_src, ip_dst, sport, dport, flags, ttl, payload, size))

            # Log packet details to a CSV file
            try:
                with open('packet_log.csv', mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([packet_time, protocol, ip_src, ip_dst, sport, dport, flags, ttl, payload, size])
            except IOError as e:
                print(f"Error writing to CSV file: {e}")

            # Check for high traffic packets
            if size > HIGH_TRAFFIC_THRESHOLD:
                high_traffic_packets.append((packet_time, protocol, ip_src, ip_dst, sport, dport, flags, ttl, payload, size))
                if high_traffic_text_widget.winfo_exists():
                    high_traffic_text_widget.insert(tk.END, packet_info)
                    high_traffic_text_widget.see(tk.END)
            
            # Update GUI if the widgets still exist
            if text_widget.winfo_exists():
                text_widget.insert(tk.END, packet_info)
                text_widget.see(tk.END)

            packet_count += 1
            if packet_count >= packet_limit:
                packet_count = 0
                if text_widget.winfo_exists():
                    text_widget.delete(1.0, tk.END)
            
            # Update packet count and time for visualization
            packet_counts.append(len(captured_packets))
            time_elapsed.append(elapsed_time)
            
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to apply filters and display matched packets
def apply_filters():
    if filtered_text_widget.winfo_exists():
        filtered_text_widget.delete(1.0, tk.END)  # Clear previous results
        for packet_info in captured_packets:
            packet_time, protocol, ip_src, ip_dst, sport, dport, flags, ttl, payload, size = packet_info

            try:
                # Apply filters
                if protocol_filter.get() != "All" and protocol_filter.get() != protocol:
                    continue
                if src_ip_filter.get() and src_ip_filter.get() != ip_src:
                    continue
                if dst_ip_filter.get() and dst_ip_filter.get() != ip_dst:
                    continue
                if port_filter.get() and (str(sport) != port_filter.get() and str(dport) != port_filter.get()):
                    continue

                # Display matched packets in the filtered text widget
                filtered_packet_info = (f"[{packet_time}] {protocol} Packet: {ip_src} -> {ip_dst} (Sport: {sport}, "
                                        f"Dport: {dport}, Flags: {flags}, TTL: {ttl}, Size: {size} bytes)\nPayload: {payload}\n\n")
                filtered_text_widget.insert(tk.END, filtered_packet_info)
                filtered_text_widget.see(tk.END)
            except Exception as e:
                print(f"Error applying filters: {e}")

# Function to start sniffing in a separate thread
def start_sniffing():
    sniffing.set()
    try:
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing.is_set())  # Capture indefinitely
    except Exception as e:
        print(f"Error starting packet sniffing: {e}")

# Function to stop sniffing
def stop_sniffing():
    sniffing.clear()

# Function to restart sniffing
def restart_sniffing():
    global packet_count, start_time
    packet_count = 0
    start_time = None
    if text_widget.winfo_exists():
        text_widget.delete(1.0, tk.END)
    if filtered_text_widget.winfo_exists():
        filtered_text_widget.delete(1.0, tk.END)
    if high_traffic_text_widget.winfo_exists():
        high_traffic_text_widget.delete(1.0, tk.END)
    captured_packets.clear()
    packet_counts.clear()
    time_elapsed.clear()
    high_traffic_packets.clear()
    stop_sniffing()
    threading.Thread(target=start_sniffing).start()

# Function to create filtering options
def create_filter_options():
    filter_frame = tk.Frame(bottom_frame)
    filter_frame.pack(fill=tk.X, padx=10, pady=5)

    control_frame = tk.Frame(filter_frame)
    control_frame.grid(row=0, column=0, padx=5, pady=5, sticky='w')

    start_button = tk.Button(control_frame, text="Start", command=lambda: threading.Thread(target=start_sniffing).start())
    start_button.grid(row=0, column=0, padx=5, pady=5, sticky='w')

    stop_button = tk.Button(control_frame, text="Stop", command=stop_sniffing)
    stop_button.grid(row=0, column=1, padx=5, pady=5, sticky='w')

    restart_button = tk.Button(control_frame, text="Restart", command=restart_sniffing)
    restart_button.grid(row=0, column=2, padx=5, pady=5, sticky='w')

    filter_control_frame = tk.Frame(filter_frame)
    filter_control_frame.grid(row=0, column=1, padx=5, pady=5, sticky='w')

    tk.Label(filter_control_frame, text="Protocol:").grid(row=0, column=0, sticky='w')
    protocol_menu = tk.OptionMenu(filter_control_frame, protocol_filter, "All", "TCP", "UDP", "Other")
    protocol_menu.grid(row=0, column=1, sticky='w')

    tk.Label(filter_control_frame, text="Source IP:").grid(row=1, column=0, sticky='w')
    src_ip_entry = tk.Entry(filter_control_frame, textvariable=src_ip_filter)
    src_ip_entry.grid(row=1, column=1, sticky='w')

    tk.Label(filter_control_frame, text="Destination IP:").grid(row=2, column=0, sticky='w')
    dst_ip_entry = tk.Entry(filter_control_frame, textvariable=dst_ip_filter)
    dst_ip_entry.grid(row=2, column=1, sticky='w')

    tk.Label(filter_control_frame, text="Port:").grid(row=3, column=0, sticky='w')
    port_entry = tk.Entry(filter_control_frame, textvariable=port_filter)
    port_entry.grid(row=3, column=1, sticky='w')

    filter_button = tk.Button(filter_control_frame, text="Filter", command=apply_filters)
    filter_button.grid(row=4, column=0, columnspan=2, pady=5, sticky='w')

create_filter_options()

# Visualization: Create a matplotlib figure and axis
fig, ax = plt.subplots(figsize=(6, 4))  # Make the figure smaller
ax.set_title("Packet Traffic Over Time")
ax.set_xlabel("Time (s)")
ax.set_ylabel("Packet Count")

# Function to update the graph
def update_graph(i):
    ax.clear()
    ax.plot(time_elapsed, packet_counts, label="Packets")
    ax.set_title("Packet Traffic Over Time")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packet Count")
    ax.legend(loc="upper right")

# Create a canvas to embed the matplotlib figure
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Start the animation
ani = FuncAnimation(fig, update_graph, interval=1000, cache_frame_data=False)

# Start the GUI event loop
root.mainloop()
