import sqlite3
import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.ttk import Progressbar, Treeview
from mac_vendor_lookup import MacLookup
import csv
import ipaddress
from openpyxl import load_workbook
from connecting import ImportData

# Update data from Excel
def update_data():
    messagebox.showinfo("Updated", "Successfully Updated data From Excel ")

# Database connect
def connect_database():
    conn = sqlite3.connect("networkss.db")
    return conn

# # fetch device records from the database
# def fetch_device():
#     conn = connect_database()
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM devices")
#     records = cursor.fetchall()
#     conn.close()
#     return records
# '''
# # Add device to the database
# def add_device():
#     ip = name_entry.get()
#     mac = phone_entry.get()
#     manufacturer = email_entry.get()'''
#
#     #
#     # if not ip:
#     #     messagebox.showwarning("Input Error", "IP is required.")
#     #     return
#     #
#     # conn = connect_database()
#     # cursor = conn.cursor()
#     # cursor.execute('''
#     #     # INSERT INTO customers (ip, mac, manufacturer)
#     #     # VALUES (?, ?, ?, ?, ?)
#   # '''  , ())
#   #   conn.commit()
#   #   conn.close()
#   #
#   #   # Write the new record to the Excel file
#   #   excel_file = 'network.xlsx'
#   #   workbook = load_workbook(excel_file)
#   #   sheet = workbook.active
#   #   new_row = [ip, mac, manufacturer]
#   #   sheet.append(new_row)
#   #   workbook.save(excel_file)
#   #
#   #   messagebox.showinfo("Success", "Device added successfully!")
#   #   clear_inputs()
#   #   populate_table()
#   #
#
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
                manuf = "Unknown"
            targets.append({"ip": received.psrc, "mac": received.hwsrc, "manuf": manuf})

            # Update progress
            current_progress += step
            progress_var.set(current_progress)
            app.update_idletasks()

        progress_var.set(100)  # Ensure progress bar hits 100% at the end
        return targets
    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {e}")
        return []


# def save_results():
#     """Save the scan results to a CSV file."""
#     file_path = tk.filedialog.asksaveasfilename(
#         defaultextension=".csv",
#         filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
#         title="Save Scan Results"
#     )
#     if not file_path:
#         return
#
#     with open(file_path, mode="w", newline="", encoding="utf-8") as file:
#         writer = csv.writer(file)
#         writer.writerow(["IP Address", "MAC Address", "Manufacturer"])
#         for row in result_table.get_children():
#             writer.writerow(result_table.item(row)["values"])
#
#     tk.messagebox.showinfo("Success", f"Results saved to {file_path}")


class Scan:
    def __init__(self, ip, mac, manufacturer):
        self.ip = ip
        self.mac = mac
        self.manufacturer = manufacturer

class Application(tk.Tk):
    # self.result_table: Treeview

    def __init__(self):
        super().__init__()
        self.title("Internet Security")

        # Container for the sections
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)

        #Define the Sections
        self.home_frame = tk.Frame(self.container, bg="black")
        self.scan_frame = tk.Frame(self.container, bg="green")
        self.sign_frame = tk.Frame(self.container, bg="green")

        self.show_sign()



        '''
        This is Home Section
        '''
        self.navbar = tk.Frame(self.home_frame, bg="yellow")
        self.navbar.pack(side=tk.TOP, fill=tk.X)
        self.label_title = tk.Label(self.navbar, text="St. Mark Hospital - ", bg="skyblue", fg="black",
                                    font=("Arial", 24))
        self.label_title.pack(side=tk.TOP, padx=10, pady=5)

        # Sign in/out Button
        self.sign_button = tk.Button(self.navbar, text="Sign Out", command=self.show_sign, bg="#2c3e50", fg="black")
        self.sign_button.pack(side=tk.LEFT, padx=10)

        home_label = tk.Label(self.home_frame, text="Welcome to the Home Section!")
        home_label.pack()
        # Content Frame with Light Blue Background
        self.content_frame = tk.Frame(self.home_frame, bg="#b2e0f0")  # Light blue background
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        #Buttons at home page
        scan_button = tk.Button(self.content_frame, bg="yellow", text="Scan", command=self.show_scan,
                                fg="yellow", background="black")
        scan_button.pack(pady=20)




        '''------
        SIGN IN PAGE 
        ----
'''
        self.navbar = tk.Frame(self.sign_frame, bg="skyblue")
        self.navbar.pack(side=tk.TOP, fill=tk.X)
        self.label_title = tk.Label(self.navbar, text="St. Mark Hospital -  ", bg="skyblue", fg="black",
                                    font=("Arial", 24))
        self.label_title.pack(side=tk.TOP, padx=10, pady=5)

        sign_label = tk.Label(self.sign_frame, text="Every Step of the Way")
        sign_label.pack()

        # Enter the user and credentials
        users = {
            "shaddy": "shaddy123",
            "mark": "mark123",
            "nurse": "nurse123"
        }

        # Function to validate sign-in credentials
        def validate_signin():
            username = self.entry_username.get()
            password = self.entry_password.get()

            if username in users and users[username] == password:
                messagebox.showinfo("Success", "Successfully Signed In")
                show_dashboard()

                # self.clear_staff_fields()
            else:
                self.clear_sign_fields()
                messagebox.showerror("Login Error", "Invalid username or password.")

            # Show the home frame after signing

        def show_dashboard():
            # self.finance_frame.pack_forget()
            # self.appointment_frame.pack_forget()
            # self.patient_frame.pack_forget()
            self.scan_frame.pack_forget()
            self.sign_frame.pack_forget()

            # Show home frame
            self.home_frame.pack(side="top", fill="both", expand=True)

        # Sign Entry Form
        self.entry_frame = tk.Frame(self.sign_frame, bg="#b2e0f0")  # Light blue background
        self.entry_frame.pack(pady=10)

        self.label_username = tk.Label(self.entry_frame, text="Username:")
        self.label_username.grid(row=1, column=0, padx=5, pady=5)
        self.entry_username = tk.Entry(self.entry_frame)
        self.entry_username.grid(row=1, column=1, padx=5, pady=5)

        self.label_password = tk.Label(self.entry_frame, text="Password:")
        self.label_password.grid(row=2, column=0, padx=5, pady=5)
        self.entry_password = tk.Entry(self.entry_frame)
        self.entry_password.grid(row=2, column=1, padx=5, pady=5)
        #        self.entry_password.insert(0, "Password")

        button_signin = tk.Button(self.sign_frame, text="Sign In", font="Arial", bg="Red", fg="white",
                                  command=validate_signin)
        button_signin.pack(pady=20)




        ''''''''''''''''
            ----------------
            SCANNING PAGE
            -----------------
        '''''''''''''''
        # TITLE
        self.navbar = tk.Frame(self.scan_frame, bg="skyblue")
        self.navbar.pack(side=tk.TOP, fill=tk.X)
        self.label_title = tk.Label(self.navbar, text="SCAN DEVICES", bg="skyblue", fg="black",
                                    font=("Arial", 24))
        self.label_title.pack(side=tk.TOP, padx=10, pady=5)
        # Home Button
        self.home_button = tk.Button(self.navbar, text="Home", command=self.show_home, bg="#2c3e50", fg="black")
        self.home_button.pack(side=tk.LEFT, padx=10)

        title_label = tk.Label(self.scan_frame, text="Network Scanner", font=("Helvetica", 28, "bold"), fg="#00ffcc", bg="#121212")
        title_label.pack(pady=10)

        # IP range input frame
        input_frame = tk.Frame(self.scan_frame, bg="#1f1f2e")
        input_frame.pack(pady=20, fill="x")
        ip_label = tk.Label(input_frame, text="Enter IP Range:", font=("Helvetica", 16), fg="#00ffcc", bg="#121212")
        ip_label.grid(row=0, column=0, padx=10)
        self.ip_entry = tk.Entry(input_frame, font=("Helvetica", 14), width=30, bg="#2e2e3e", fg="white", insertbackground="white")
        self.ip_entry.grid(row=0, column=1, padx=10)

        # Separate frame for the Scan button
        button_frame = tk.Frame(self.scan_frame, bg="#121212")  # A new frame for the button
        button_frame.pack(pady=10)
        scan_button = tk.Button(button_frame, text="Scan", font=("Helvetica", 14, "bold"), bg="#00cc99", fg="black", relief="flat", command=self.start_scan)
        scan_button.pack()

        # Progress bar
        self.progress_var = tk.IntVar()
        self.progress_bar = Progressbar(self.scan_frame, orient="horizontal", length=700, mode="determinate", variable=self.progress_var)
        self.progress_bar.pack(pady=10)

        # Results table starting with the Frame
        result_frame = tk.Frame(self.scan_frame, bg="#1f1f2e")
        result_frame.pack(pady=20)

        columns = ("Ip", "Mac", "Manufacturer")  # Create list for columns for the table
        self.result_table = ttk.Treeview(result_frame, columns=columns, show="headings", height=15)
        self.result_table.column("Ip", width=200)
        self.result_table.column("Mac", width=200)
        self.result_table.column("Manufacturer", width=200)
        self.result_table.heading("Ip", text="Ip Address")
        self.result_table.heading("Mac", text="Mac Address")
        self.result_table.heading("Manufacturer", text="Manufacturer")

        # Table Styling
        style = ttk.Style()
        style.configure("Treeview", background="#1e1e2e", foreground="white", rowheight=25,
                        fieldbackground="#1e1e2e", font=("Helvetica", 12))
        style.configure("Treeview.Heading", font=("Helvetica", 14, "bold"), background="#44475a", foreground="#00ffcc")
        style.map("Treeview", background=[("selected", "#00cc99")])

        self.result_table.pack(fill="both", expand=True)





        '''

        ----------------------
        FUNCTIONS TO SHOW PAGES
        ----------------------
        '''
    def show_sign(self):
            # Hide Sign frame
            self.home_frame.pack_forget()
            self.scan_frame.pack_forget()
            self.sign_frame.pack(side="top", fill="both", expand=True)

    def show_home(self):
        self.scan_frame.pack_forget()
        self.sign_frame.pack_forget()
        self.home_frame.pack(side="top", fill="both", expand=True)

    def show_scan(self):
        self.home_frame.pack_forget()
        self.sign_frame.pack_forget()
        self.scan_frame.pack(side="top", fill="both", expand=True)


    '''
-----------------
CONTROL FUNCTIONS
------------------
    '''

    def clear_sign_fields(self):
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)

    def start_scan(self):
        """Trigger the scan process and handle input validation."""
        ip_range = self.ip_entry.get().strip()  # Get and clean the input

        if not ip_range:
            # Show a warning message if no input is provided
            messagebox.showwarning("Input Required", "Please enter an IP range before scanning.")
            return

        if not validate_ip_range(ip_range):
            # Show an error message if the IP range is invalid
            messagebox.showerror("Invalid Input",
                                 "The IP range you entered is not valid.\nExample format: 192.168.1.0/24")
            return

        # Reset progress bar
        self.progress_var.set(0)

        try:
            # Perform scan
            results = scan(ip_range, self.progress_var)

            # Clear the table
            for item in self.result_table.get_children():
                self.result_table.delete(item)

            # Display results in the table
            for client in results:
                self.result_table.insert("", "end", values=(client["ip"], client["mac"], client["manuf"]))

            if not results:
                messagebox.showinfo("No Results", "No devices were found in the specified IP range.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    app = Application()
    app.mainloop()



