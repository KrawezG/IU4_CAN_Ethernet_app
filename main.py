import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import time
import math

# Device configuration
DEVICE_IP = "169.254.22.238"
DEVICE_PORT = 33333
HEARTBEAT_MESSAGE = b"99999"
HEARTBEAT_RESPONSE = b"99998"
HEARTBEAT_INTERVAL = 5  # seconds

# GUI Application
class CANApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CAN-Ethernet Converter")

        # Socket for communication
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1)

        # Connection status
        self.connected = False
        self.status_label = tk.Label(root, text="Status: Disconnected", fg="red")
        self.status_label.pack(pady=5)

        # Transmit CAN message frame
        transmit_frame = tk.LabelFrame(root, text="Transmit CAN Message", padx=10, pady=10)
        transmit_frame.pack(fill="x", padx=10, pady=5)

        self.id_label = tk.Label(transmit_frame, text="ID (hex, 2 bytes):")
        self.id_label.grid(row=0, column=0, padx=5, pady=5)
        self.id_entry = tk.Entry(transmit_frame, width=10)
        self.id_entry.grid(row=0, column=1, padx=5, pady=5)
        self.id_entry.bind("<KeyRelease>", lambda event: self.validate_hex_input(self.id_entry, 4))

        self.data_label = tk.Label(transmit_frame, text="Data (hex, up to 8 bytes):")
        self.data_label.grid(row=1, column=0, padx=5, pady=5)

        # Data entry with byte count
        self.data_frame = tk.Frame(transmit_frame)
        self.data_frame.grid(row=1, column=1, padx=5, pady=5)
        self.data_entry = tk.Entry(self.data_frame, width=20)
        self.data_entry.pack(side="left")
        self.byte_count_label = tk.Label(self.data_frame, text="0/8 bytes", fg="gray")
        self.byte_count_label.pack(side="right", padx=5)

        self.data_entry.bind("<KeyRelease>", lambda event: self.validate_hex_input(self.data_entry, 16))
        self.data_entry.bind("<KeyRelease>", self.update_byte_count)

        self.length_label = tk.Label(transmit_frame, text="Length (calculated):")
        self.length_label.grid(row=2, column=0, padx=5, pady=5)
        self.length_entry = tk.Entry(transmit_frame, width=10, state="readonly")
        self.length_entry.grid(row=2, column=1, padx=5, pady=5)

        self.send_button = tk.Button(transmit_frame, text="Send", command=self.send_message)
        self.send_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Message log frame
        log_frame = tk.LabelFrame(root, text="Message Log", padx=10, pady=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, width=60, height=20, wrap=tk.WORD, state="disabled")
        self.log_area.pack(fill="both", expand=True)

        # Start threads for connection check and listener
        self.running = True
        threading.Thread(target=self.check_connection, daemon=True).start()
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def validate_hex_input(self, entry, max_length):
        """Ensure the entry contains only valid hex characters and is within the max length."""
        text = entry.get()
        valid_text = "".join(c for c in text if c.lower() in "0123456789abcdef")[:max_length]
        if text != valid_text:
            entry.delete(0, tk.END)
            entry.insert(0, valid_text)

    def update_byte_count(self, event=None):
        """Update byte count, validate data input, and calculate length."""
        hex_data = self.data_entry.get()
        byte_count = math.ceil(len(hex_data) / 2)  # Calculate the number of bytes (round up)

        # Update byte count label
        self.byte_count_label.config(text=f"{byte_count}/8 bytes")
        if byte_count > 8:
            self.byte_count_label.config(fg="red")
        else:
            self.byte_count_label.config(fg="gray")

        # Update the calculated length in the length field
        self.length_entry.config(state="normal")
        self.length_entry.delete(0, tk.END)
        self.length_entry.insert(0, str(byte_count))
        self.length_entry.config(state="readonly")

    def send_message(self):
        if not self.connected:
            self.log("Error: Connection is down. Message not sent.")
            return

        can_id, can_length, can_data = self.validate_inputs()
        if can_id is None:
            return

        try:
            # Pack the message
            message = can_id.to_bytes(2, "little") + can_length.to_bytes(1, "little") + can_data
            self.sock.sendto(message, (DEVICE_IP, DEVICE_PORT))

            # Log sent message
            self.log(f"Sent: ID=0x{can_id:04X}, Length={can_length}, Data={can_data.hex()}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def validate_inputs(self):
        """Validate the ID and data length."""
        # Validate ID
        try:
            can_id = int(self.id_entry.get(), 16)
            if not (0x0000 <= can_id <= 0xFFFF):
                raise ValueError("ID out of range")
        except ValueError:
            messagebox.showerror("Error", "Invalid CAN ID! Must be 2 bytes (hex).")
            return None, None, None

        # Validate Data
        hex_data = self.data_entry.get()
        try:
            can_data = bytes.fromhex(hex_data) if hex_data else b""
        except ValueError:
            messagebox.showerror("Error", "Invalid data format! Must be valid hex.")
            return None, None, None

        # Get length from field
        can_length = math.ceil(len(can_data))  # Updated to round up

        # Adjust data if necessary
        if len(can_data) < 8:
            can_data = can_data.ljust(8, b'\x00')
            self.log(f"Data padded to 8 bytes: {can_data.hex()}")

        return can_id, can_length, can_data

    def listen_for_messages(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)
                if data == HEARTBEAT_RESPONSE:
                    self.connected = True
                    self.update_status(True)
                elif len(data) >= 11:
                    can_id = int.from_bytes(data[0:2], "little")
                    can_length = data[2]
                    can_data = data[3:11]
                    self.log(f"Received: ID=0x{can_id:04X}, Length={can_length}, Data={can_data.hex()}")
            except socket.timeout:
                pass
            except Exception as e:
                self.log(f"Error receiving data: {e}")

    def check_connection(self):
        while self.running:
            try:
                self.sock.sendto(HEARTBEAT_MESSAGE, (DEVICE_IP, DEVICE_PORT))
                time.sleep(HEARTBEAT_INTERVAL)
                if not self.connected:
                    self.update_status(False)
            except Exception as e:
                self.log(f"Error checking connection: {e}")
                self.update_status(False)

    def update_status(self, is_connected):
        if is_connected:
            self.status_label.config(text="Status: Connected", fg="green")
        else:
            self.status_label.config(text="Status: Disconnected", fg="red")
        self.connected = is_connected

    def log(self, message):
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.yview(tk.END)
        self.log_area.config(state="disabled")

    def on_close(self):
        self.running = False
        self.sock.close()
        self.root.destroy()

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = CANApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
