# C:\Users\user\OneDrive\Υπολογιστής\HY458-Project\dummy_code2

import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import subprocess
import os
from PIL import Image, ImageTk
import ctypes
import fitz
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scanner import initialize_database

ctypes.windll.shcore.SetProcessDpiAwareness(1)

DB_FILE = "crypto_scan_results.db"

class CryptoScannerApp:
    def __init__(self, root):
        """Initialize the main application window in maximized mode."""
        self.root = root
        self.root.title("CipherEvolve")

        initialize_database()

        # Open window in maximized state
        self.root.state('zoomed')  # This will set it to maximized mode (shows ⛶ instead of □)

        self.root.configure(bg="#2C3E50")  # Dark background for a modern look

        # Apply ttk theme
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use a more modern-looking theme
        self.style.configure("Treeview", background="#ECF0F1", foreground="black", rowheight=25, font=("Arial", 12))
        self.style.configure("Treeview.Heading", font=("Arial", 13, "bold"), background="#34495E", foreground="white")
        self.style.configure("TButton", font=("Arial", 12, "bold"), padding=6)

        # Setup UI
        self.setup_ui()

    def exit_fullscreen(self, event=None):
        """Exit full screen mode when the Escape key is pressed."""
        self.root.attributes('-fullscreen', False)

    def setup_ui(self):
        """Set up the user interface elements."""
        # Frame for path input
        path_frame = tk.Frame(self.root, bg="#2C3E50")
        path_frame.pack(pady=10, padx=20, fill=tk.X)

        self.path_label = tk.Label(path_frame, text="Enter Folder Path:", fg="white", bg="#2C3E50", font=("Arial", 12))
        self.path_label.pack(side=tk.LEFT, padx=5)

        self.path_entry = ttk.Entry(path_frame, width=50, font=("Arial", 12))
        self.path_entry.pack(side=tk.LEFT, padx=5)

        # Frame for search bar
        search_frame = tk.Frame(self.root, bg="#2C3E50")
        search_frame.pack(pady=5, padx=20, fill=tk.X)

        search_label = tk.Label(search_frame, text="Search Filename:", fg="white", bg="#2C3E50", font=("Arial", 12))
        search_label.pack(side=tk.LEFT, padx=5)

        self.search_entry = ttk.Entry(search_frame, width=40, font=("Arial", 12))
        self.search_entry.pack(side=tk.LEFT, padx=5)

        search_btn = ttk.Button(search_frame, text="🔍 Search", command=self.search_file)
        search_btn.pack(side=tk.LEFT, padx=10)

        # Frame for table
        table_frame = tk.Frame(self.root, bg="#2C3E50")
        table_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        # Scrollbar
        self.tree_scroll = ttk.Scrollbar(table_frame)
        self.tree_scroll.pack(side="right", fill="y")

        # Treeview (Table)
        self.tree = ttk.Treeview(table_frame, columns=(
            "Filename", "Language", "Line Number", "Vulnerable Code", "Risk Level", "Fixed Code", "New Risk Level"),
                                 show="headings", yscrollcommand=self.tree_scroll.set)

        self.tree.heading("Filename", text="Filename")
        self.tree.heading("Language", text="Language")
        self.tree.heading("Line Number", text="Line Number")
        self.tree.heading("Vulnerable Code", text="Vulnerable Code")
        self.tree.heading("Risk Level", text="Risk Level")
        self.tree.heading("Fixed Code", text="Fixed Code")
        self.tree.heading("New Risk Level", text="New Risk Level")

        # Adjust column widths
        self.tree.column("Filename", width=200, anchor="center")
        self.tree.column("Language", width=100, anchor="center")
        self.tree.column("Line Number", width=100, anchor="center")
        self.tree.column("Vulnerable Code", width=350, anchor="center")
        self.tree.column("Risk Level", width=120, anchor="center")
        self.tree.column("Fixed Code", width=350, anchor="center")
        self.tree.column("New Risk Level", width=120, anchor="center")

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree_scroll.config(command=self.tree.yview)

        # Buttons frame
        button_frame = tk.Frame(self.root, bg="#2C3E50")
        button_frame.pack(pady=10)

        self.btn_scan = ttk.Button(button_frame, text="🔍 Scan New Folder", command=self.scan_new_folder)
        self.btn_scan.grid(row=0, column=0, padx=10)

        self.btn_refresh = ttk.Button(button_frame, text="🔄 Refresh Results", command=self.populate_table)
        self.btn_refresh.grid(row=0, column=1, padx=10)

        self.btn_fix_vulnerabilities = ttk.Button(button_frame, text="🔧 Fix Vulnerabilities",
                                                  command=self.fix_vulnerabilities)
        self.btn_fix_vulnerabilities.grid(row=0, column=2, padx=10)

        stats_btn = ttk.Button(button_frame, text="📊 Statistics", command=self.show_statistics)
        stats_btn.grid(row=0, column=3, padx=10)

        help_btn = ttk.Button(button_frame, text="📖 Help", command=self.open_pdf_manual)
        help_btn.grid(row=0, column=4, padx=10)

    def fetch_results(self, search_query=""):
        """Fetch scan results, including new risk level."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            if search_query:
                cursor.execute("""
                    SELECT filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level 
                    FROM findings WHERE filename LIKE ? ORDER BY filename, risk_level DESC
                """, (f"%{search_query}%",))
            else:
                cursor.execute("""
                    SELECT filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level 
                    FROM findings ORDER BY filename, risk_level DESC
                """)

            results = cursor.fetchall()
            conn.close()
            return results

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error fetching results: {e}", parent=self.root)
            return []

    def populate_table(self, search_query=""):
        """Populate the table with scan results, filtering by search_query if provided."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        if search_query:
            cursor.execute("""
                SELECT filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level 
                FROM findings WHERE filename LIKE ? ORDER BY filename, risk_level DESC
            """, (f"%{search_query}%",))
        else:
            cursor.execute("""
                SELECT filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level 
                FROM findings ORDER BY filename, risk_level DESC
            """)

        results = cursor.fetchall()
        conn.close()

        for result in results:
            filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level = result
            self.tree.insert("", "end",
                             values=(
                             filename, language, line_number, vulnerable_code, risk_level, fixed_code, new_risk_level))

    def scan_new_folder(self):
        """Trigger the scanning process using user-specified path."""
        folder_path = self.path_entry.get().strip()

        if not folder_path:
            messagebox.showwarning("Input Required", "Please enter a valid folder path.")
            return

        if not os.path.exists(folder_path):
            messagebox.showerror("Invalid Path", "The specified folder path does not exist. Please enter a valid path.")
            return

        try:
            subprocess.run(["python", "scanner.py", folder_path], check=True)
            messagebox.showinfo("Scan Complete", "Scanning completed successfully!")
            self.populate_table()
        except subprocess.CalledProcessError:
            messagebox.showerror("Scan Error", "Error running scanner script.")

    def fix_vulnerabilities(self):
        """Automatically replaces weak cryptographic code in each detected vulnerable file."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # Fetch vulnerable code and replacements
            cursor.execute(
                "SELECT filename, line_number, vulnerable_code, fixed_code FROM findings WHERE risk_level IN ('HIGH', 'MEDIUM')")
            results = cursor.fetchall()

            if not results:
                messagebox.showinfo("No Fixes Needed", "No vulnerabilities found that require fixing!")
                return

            file_modifications = {}

            # Modify files in-place
            for filename, line_number, vulnerable_code, fixed_code in results:
                file_path = os.path.join(self.path_entry.get().strip(), filename)
                if not os.path.exists(file_path):
                    continue

                # Read file contents
                with open(file_path, "r", encoding="utf-8") as file:
                    lines = file.readlines()

                # Modify the specific line
                modified = False
                if 1 <= line_number <= len(lines):
                    if vulnerable_code in lines[line_number - 1]:  # Ensure it's the correct line
                        lines[line_number - 1] = lines[line_number - 1].replace(vulnerable_code, fixed_code)
                        modified = True

                # Write back changes if modifications were made
                if modified:
                    with open(file_path, "w", encoding="utf-8") as file:
                        file.writelines(lines)

                    file_modifications[file_path] = (vulnerable_code, fixed_code)

            conn.close()

            if file_modifications:
                messagebox.showinfo("Fixes Applied", f"Fixed vulnerabilities in {len(file_modifications)} files!")
            else:
                messagebox.showinfo("No Changes", "No modifications were needed.")

            self.populate_table()  # Refresh table with updated results

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while fixing vulnerabilities: {e}")

    def search_file(self):
        """Search for files by filename."""
        search_query = self.search_entry.get().strip()
        self.populate_table(search_query)

    def open_pdf_manual(self):
        """Opens a new window displaying the PDF manual as images and disables the main window."""
        pdf_path = "Resources/app_manual_chapter4.pdf"

        if not os.path.exists(pdf_path):
            messagebox.showerror("Error", "Manual PDF not found!")
            return

        # Open PDF and get the first page dimensions
        pdf_doc = fitz.open(pdf_path)
        first_page = pdf_doc[0]
        pix = first_page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))  # Scale by 1.5 for clarity
        pdf_width, pdf_height = pix.width, pix.height

        # Set max height for the window
        max_height = 600
        window_height = min(pdf_height, max_height)

        # Create a new window for the PDF
        self.pdf_window = tk.Toplevel(self.root)
        self.pdf_window.title("Application Manual")

        # Set window size based on PDF width and capped height
        self.pdf_window.geometry(f"{pdf_width}x{window_height}")
        self.pdf_window.resizable(False, False)

        # Center the window on the screen
        screen_width = self.pdf_window.winfo_screenwidth()
        screen_height = self.pdf_window.winfo_screenheight()
        x_position = int((screen_width / 2) - (pdf_width / 2))
        y_position = int((screen_height / 2) - (window_height / 2))
        self.pdf_window.geometry(f"+{x_position}+{y_position}")

        # Disable the main window while PDF window is open
        self.root.attributes("-disabled", True)

        # When the PDF window is closed, re-enable the main window
        self.pdf_window.protocol("WM_DELETE_WINDOW", self.close_pdf_window)

        # Create a scrollbar for vertical scrolling
        canvas = tk.Canvas(self.pdf_window, width=pdf_width, height=window_height)
        scrollbar = ttk.Scrollbar(self.pdf_window, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas)

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Render the PDF pages
        self.pdf_images = []
        for page_num in range(len(pdf_doc)):
            page = pdf_doc[page_num]
            pix = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5))
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            img_tk = ImageTk.PhotoImage(img)

            self.pdf_images.append(img_tk)
            label = tk.Label(scroll_frame, image=img_tk)
            label.pack(pady=5)

        self.pdf_window.mainloop()

    def close_pdf_window(self):
        """Re-enables the main application window after closing the PDF viewer."""
        self.root.attributes("-disabled", False)
        self.pdf_window.destroy()

    def show_statistics(self):
        """Show statistics about scanned code as a graph."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()

            # Count vulnerable lines based on new_risk_level
            cursor.execute("SELECT COUNT(*) FROM findings WHERE new_risk_level IN ('HIGH', 'MEDIUM', 'LOW')")
            vulnerable_lines = cursor.fetchone()[0]

            # Count secure lines based on new_risk_level
            cursor.execute("SELECT COUNT(*) FROM findings WHERE new_risk_level = 'SECURE'")
            secure_lines = cursor.fetchone()[0]

            # Total lines
            total_lines = vulnerable_lines + secure_lines

            if total_lines == 0:
                messagebox.showinfo("Statistics", "No code has been scanned yet.")
                return

            # Pie chart data
            labels = ['Vulnerable Lines', 'Secure Lines']
            sizes = [vulnerable_lines, secure_lines]
            colors = ['#E74C3C', '#2ECC71']

            # Create a new window for the chart
            stats_window = tk.Toplevel(self.root)
            stats_window.title("Scan Statistics")
            stats_window.geometry("900x700")

            # Plotting
            fig, ax = plt.subplots(figsize=(6, 6))
            ax.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                startangle=140,
                colors=colors,
                labeldistance=1.15,  # Move labels further out
                textprops={'fontsize': 12}  # Adjust font size if needed
            )
            ax.axis('equal')  # Ensures the pie is a circle

            plt.tight_layout()  # Ensure everything fits nicely

            # Embed the plot in Tkinter window
            canvas = FigureCanvasTkAgg(fig, master=stats_window)
            canvas.draw()
            canvas.get_tk_widget().pack()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error fetching statistics: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoScannerApp(root)
    root.mainloop()