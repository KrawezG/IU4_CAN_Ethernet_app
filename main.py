import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import time
import math

# Device configuration
DEVICE_IP = "169.254.22.238"
DEVICE_PORT = 33333
HEARTBEAT_MESSAGE = b"\x39\x39\x39\x39\x39"  # "99999" in ASCII hex
HEARTBEAT_RESPONSE = b"\x39\x39\x39\x39\x38"  # "99998" in ASCII hex
HEARTBEAT_INTERVAL = 5  # seconds
TIMEOUT_INTERVAL = 10  # seconds

# Global variables
connected = False
running = True
last_heartbeat_time = 0
hide_duplicate_messages = True  # Flag to hide duplicate messages
last_sent_message = None
last_received_message = None

def validate_hex_input(entry, max_length):
    """Ensure the entry contains only valid hex characters and is within the max length."""
    text = entry.get()
    valid_text = "".join(c for c in text if c.lower() in "0123456789abcdef")[:max_length]
    if text != valid_text:
        entry.delete(0, tk.END)
        entry.insert(0, valid_text)

    # If this is the Data field, update the byte count
    if entry == data_entry:
        update_byte_count()

def update_byte_count():
    """Update byte count, validate data input, and calculate length."""
    hex_data = data_entry.get()
    byte_count = math.ceil(len(hex_data) / 2)  # Calculate the number of bytes (round up)

    # Enforce max length (8 bytes or 16 hex characters)
    if byte_count > 8:
        byte_count = 8
        data_entry.delete(16, tk.END)  # Truncate to 16 hex characters
        hex_data = data_entry.get()  # Refresh truncated data

    # Update byte count label
    byte_count_label.config(text=f"{byte_count}/8 bytes")
    if byte_count > 8:
        byte_count_label.config(fg="red")
    else:
        byte_count_label.config(fg="gray")

    # Update the calculated length in the length field
    length_entry.config(state="normal")
    length_entry.delete(0, tk.END)
    length_entry.insert(0, str(byte_count))
    length_entry.config(state="readonly")

def send_message():
    global connected, last_sent_message

    # Check if connected
    if not connected:
        log("Error: Connection is down. Message not sent.")
        return

    # Validate ID
    can_id_text = id_entry.get().strip()
    if not can_id_text:
        messagebox.showerror("Error", "ID field is required!")
        return
    try:
        can_id = int(can_id_text, 16)
        if not (0x0000 <= can_id <= 0xFFFF):
            raise ValueError("ID out of range")
    except ValueError:
        messagebox.showerror("Error", "Invalid CAN ID! Must be a 2-byte hex value.")
        return

    # Validate Length
    can_length_text = length_entry.get().strip()
    if not can_length_text:
        messagebox.showerror("Error", "Length field is required!")
        return
    try:
        can_length = int(can_length_text)
        if not (0 <= can_length <= 8):
            raise ValueError("Length out of range")
    except ValueError:
        messagebox.showerror("Error", "Invalid Length! Must be an integer between 0 and 8.")
        return

    # Validate Data
    hex_data = data_entry.get()
    try:
        can_data = bytes.fromhex(hex_data) if hex_data else b""
    except ValueError:
        messagebox.showerror("Error", "Invalid data format! Must be valid hex.")
        return

    # Adjust data if necessary
    if len(can_data) < 8:
        can_data = can_data.ljust(8, b'\x00')
        log(f"Data padded to 8 bytes: {can_data.hex()}")

    # Pack and send the message
    try:
        message = can_id.to_bytes(2, "little") + can_length.to_bytes(1, "little") + can_data
        sock.sendto(message, (DEVICE_IP, DEVICE_PORT))
        last_sent_message = message
        log(f"Sent: ID=0x{can_id:04X}, Length={can_length}, Data={can_data.hex()}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send message: {e}")

def log(message):
    log_area.config(state="normal")
    log_area.insert(tk.END, message + "\n")
    log_area.yview(tk.END)
    log_area.config(state="disabled")

def update_status(is_connected):
    global connected
    if is_connected:
        status_label.config(text="Status: Connected", fg="green")
    else:
        status_label.config(text="Status: Disconnected", fg="red")
    connected = is_connected

def heartbeat_monitor():
    global connected, last_heartbeat_time
    while running:
        try:
            sock.sendto(HEARTBEAT_MESSAGE, (DEVICE_IP, DEVICE_PORT))
            # log("Heartbeat sent.")
            time.sleep(HEARTBEAT_INTERVAL)
            current_time = time.time()
            if current_time - last_heartbeat_time > TIMEOUT_INTERVAL:
                update_status(False)
        except Exception as e:
            log(f"Error in heartbeat: {e}")
            update_status(False)

def listen_for_messages():
    global last_heartbeat_time, last_received_message
    while running:
        try:
            data, _ = sock.recvfrom(1024)
            if data == HEARTBEAT_RESPONSE:
                last_heartbeat_time = time.time()
                update_status(True)
                # log("Heartbeat acknowledged.")
            elif len(data) >= 11:
                if hide_duplicate_messages and data == last_sent_message:
                    continue  # Skip logging if the message is a duplicate

                last_received_message = data
                can_id = int.from_bytes(data[0:2], "little")
                can_length = data[2]
                can_data = data[3:11]
                log(f"Received: ID=0x{can_id:04X}, Length={can_length}, Data={can_data.hex()}")
        except socket.timeout:
            pass
        except Exception as e:
            log(f"Error receiving data: {e}")

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)

# Create the GUI
root = tk.Tk()
root.title("CAN-Ethernet Converter")

# Connection status
status_label = tk.Label(root, text="Status: Disconnected", fg="red")
status_label.pack(pady=5)

# Transmit CAN message frame
transmit_frame = tk.LabelFrame(root, text="Transmit CAN Message", padx=10, pady=10)
transmit_frame.pack(fill="x", padx=10, pady=5)

tk.Label(transmit_frame, text="ID (hex, 1 byte):").grid(row=0, column=0, padx=5, pady=5)
id_entry = tk.Entry(transmit_frame, width=10)
id_entry.grid(row=0, column=1, padx=5, pady=5)
id_entry.bind("<KeyRelease>", lambda event: validate_hex_input(id_entry, 4))

tk.Label(transmit_frame, text="Data (hex, up to 8 bytes):").grid(row=1, column=0, padx=5, pady=5)

data_frame = tk.Frame(transmit_frame)
data_frame.grid(row=1, column=1, padx=5, pady=5)
data_entry = tk.Entry(data_frame, width=20)
data_entry.pack(side="left")
byte_count_label = tk.Label(data_frame, text="0/8 bytes", fg="gray")
byte_count_label.pack(side="right", padx=5)

data_entry.bind("<KeyRelease>", lambda event: validate_hex_input(data_entry, 16))

tk.Label(transmit_frame, text="Length (calculated):").grid(row=2, column=0, padx=5, pady=5)
length_entry = tk.Entry(transmit_frame, width=10, state="readonly")
length_entry.grid(row=2, column=1, padx=5, pady=5)

tk.Button(transmit_frame, text="Send", command=send_message).grid(row=3, column=0, columnspan=2, pady=10)

# Message log frame
log_frame = tk.LabelFrame(root, text="Message Log", padx=10, pady=10)
log_frame.pack(fill="both", expand=True, padx=10, pady=5)

log_area = scrolledtext.ScrolledText(log_frame, width=60, height=20, wrap=tk.WORD, state="disabled")
log_area.pack(fill="both", expand=True)

# Start threads for connection check and listener
threading.Thread(target=heartbeat_monitor, daemon=True).start()
threading.Thread(target=listen_for_messages, daemon=True).start()

# Run the application
def on_close():
    global running
    running = False
    sock.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
