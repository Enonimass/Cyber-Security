import scapy.all as scapy
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.ttk import Progressbar
from mac_vendor_lookup import MacLookup
import csv
import ipaddress


def validate_ip_range(ip_range):
    """Validate the IP range format."""
    try:
        ipaddress.IPv4Network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def scan(ip, progress_var):
    """Perform the network scan and update the progress bar."""
    try:
        mac_lookup = MacLookup()
        results = scapy.arping(ip, verbose=0)
        targets = []

        # Initialize progress
        total = len(results[0])
        step = 100 // total if total else 0
        current_progress = 0

        for sent, received in results[0]:
            try:
                manuf = mac_lookup.lookup(received.hwsrc)
            except KeyError:
                manuf = "unknown"
            targets.append({"ip": received.psrc, "mac": received.hwsrc, "manuf": manuf})

            # Update progress
            current_progress += step
            progress_var.set(current_progress)
            root.update_idletasks()

        progress_var.set(100)  # Ensure progress bar hits 100% at the end
        return targets
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        return []


def start_scan():
    """Trigger the scan process."""
    ip_range = ip_entry.get()
    if not ip_range:
        messagebox.showwarning("Input Required", "Please enter an IP range.")
        return

    if not validate_ip_range(ip_range):
        messagebox.showerror("Invalid Input", "Please enter a valid IP range (e.g., 192.168.1.0/24).")
        return

    # Reset progress bar
    progress_var.set(0)

    # Perform scan
    results = scan(ip_range, progress_var)

    # Clear the table
    for item in result_table.get_children():
        result_table.delete(item)

    # Display results in the table
    for client in results:
        result_table.insert("", "end", values=(client["ip"], client["mac"], client["manuf"]))


def save_results():
    """Save the scan results to a CSV file."""
    file_path = tk.filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        title="Save Scan Results"
    )
    if not file_path:
        return

    with open(file_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "MAC Address", "Manufacturer"])
        for row in result_table.get_children():
            writer.writerow(result_table.item(row)["values"])

    messagebox.showinfo("Success", f"Results saved to {file_path}")


# Create the main window
root = tk.Tk()
root.title("Futuristic Network Scanner")
root.geometry("800x550")
root.configure(bg="black")

# Title label
title_label = tk.Label(root, text="Network Scanner", font=("Helvetica", 24, "bold"), fg="green", bg="black")
title_label.pack(pady=10)

# IP range input frame
input_frame = tk.Frame(root, bg="#1f1f2e")
input_frame.pack(pady=20)

ip_label = tk.Label(input_frame, text="Enter IP Range:", font=("Helvetica", 14), fg="green", bg="black")
ip_label.grid(row=0, column=0, padx=10)

ip_entry = tk.Entry(input_frame, font=("Helvetica", 14), width=30)
ip_entry.grid(row=0, column=1, padx=10)


# Separate frame for the Scan button
button_frame = tk.Frame(root, bg="#121212")  # A new frame for the button
button_frame.pack(pady=10)
scan_button = tk.Button(button_frame, text="Scan", font=("Helvetica", 14, "bold"), bg="#00cc99", fg="black", relief="flat", command=start_scan)
scan_button.pack()


# Progress bar
progress_var = tk.IntVar()
progress_bar = Progressbar(root, orient="horizontal", length=700, mode="determinate", variable=progress_var)
progress_bar.pack(pady=10)

# Results table
result_frame = tk.Frame(root, bg="#1f1f2e")
result_frame.pack(pady=20)

columns = ("IP Address", "MAC Address", "Manufacturer")
result_table = ttk.Treeview(result_frame, columns=columns, show="headings", height=15)
result_table.column("IP Address", width=200, anchor="center")
result_table.column("MAC Address", width=300, anchor="center")
result_table.column("Manufacturer", width=200, anchor="center")
result_table.heading("IP Address", text="IP Address")
result_table.heading("MAC Address", text="MAC Address")
result_table.heading("Manufacturer", text="Manufacturer")

# Table styling
style = ttk.Style()
style.configure("Treeview", background="#2e2e3e", foreground="#ffffff", rowheight=25,
                fieldbackground="#2e2e3e", font=("Helvetica", 12))
style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"), background="#44475a", foreground="#00ffcc")
style.map("Treeview", background=[("selected", "#00cc99")])

result_table.pack(fill="both", expand=True)

# Save button
save_button = tk.Button(root, text="Save Results", font=("Helvetica", 14, "bold"), bg="#44475a", fg="#00ffcc", relief="flat", command=save_results)
save_button.pack(pady=10)

# Separator
separator = tk.Frame(root, bg="#00ffcc", height=2, width=700)
separator.pack(pady=5)

# Run the application
root.mainloop()
