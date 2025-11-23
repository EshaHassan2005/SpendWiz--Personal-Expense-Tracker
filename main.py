import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict
from tkinter.ttk import Treeview


class ExpenseTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SpendWiz - Personal Expense Tracker")
        self.root.geometry("10000x700")
        self.root.configure(bg="#1a1a2a")
        self.current_user=None
        self.init_database()
        self.show_login_page()

    def init_database(self):
        self.conn= sqlite3.connect("expense_tracker.db")
        self.cursor=self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                type TEXT NOT NULL,
                category TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                date DATE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        self.conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_page(self):
        self.clear_window()

        # Main frame
        frame=tk.Frame(self.root,bg="#1a1a2e")
        frame.place(relx=0.5,rely=0.5,anchor="center")

        # Title
        title =(tk.Label(frame, text="SpendWiz", font=("Helvetica", 32, "bold"),bg="#1a1a2e", fg="#00d9ff"))
        title.pack(pady=20)

        # Username
        tk.Label(frame, text="Username", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(20,5))
        self.login_username= tk.Entry(frame,font=("Helvetica",14), width=30, bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.login_username.pack(anchor="w",pady=5)

        # Password
        tk.Label(frame,text="Password", font=("Helvetica",12), bg="1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10,5))
        self.login_password= tk.Entry(frame, font=("Helvetica",14), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.login_password.pack(anchor="w",pady=5)

        # Buttons
        btn_frame= tk.Frame(frame, bg="#1a1a2e")
        btn_frame.pack(pady=30)

        login_btn= tk.Button(btn_frame, text="Login", font=("Helvetica",12,"bold"), bg="#00d9ff", fg="#1a1a2e", width=12, cursor="hand2", command=self.login)
        login_btn.grid(row=0, column=0, pady=5)

        register_btn= tk.Button(btn_frame, text="Register", font=("Helvetica",12),bg="#0f3460", fg="#ffffff", width=12, cursor="hand2", command=self.show_register_page)
        register_btn.grid(row=0, column=1, pady=5)


    def show_register_page(self):
        self.clear_window()

        frame= tk.Frame(self.root,bg="#1a1a2e")
        frame.place(relx=0.5,rely=0.5,anchor="center")

        title = tk.Label(frame, text="Create Account", font=("Helvetica",28,"bold"), bg="#1a1a2e", fg="#00d9ff")
        title.pack(pady=20)

        # Username
        tk.Label(frame, text="Username", font=("Helvetica", 12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(20, 5))
        self.reg_username = tk.Entry(frame, font=("Helvetica", 14), width=30, bg="#16213e", fg="#ffffff",insertbackground="#ffffff")
        self.reg_username.pack(anchor="w", pady=5)

        # Password
        tk.Label(frame, text="Password", font=("Helvetica", 12), bg="1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_password = tk.Entry(frame, font=("Helvetica", 14), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.reg_password.pack(anchor="w", pady=5)

        # Confirm Password
        tk.Label(frame, text="Confirm Password", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_confirm = tk.Entry(frame, font=("Helvetica",14), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.reg_confirm.pack(anchor="w", pady=5)

        # Buttons
        btn_frame= tk.Frame(frame, bg="#1a1a2e")
        btn_frame.pack(pady=30)

        reg_btn = tk.Button(btn_frame, text="Register", font=("Helvetica", 12, "bold"), bg="#00d9ff", fg="#1a1a2e",
                              width=12, cursor="hand2", command=self.register)
        reg_btn.grid(row=0, column=0, pady=5)

        back_btn = tk.Button(btn_frame, text="Back to Login", font=("Helvetica", 12), bg="#0f3460", fg="#ffffff",
                                 width=12, cursor="hand2", command=self.show_login_page)
        back_btn.grid(row=0, column=1, pady=5)



    def login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return

        hashed_pw= self.hash_password(password)
        self.cursor.execute("SELECT id FROM users WHERE username = ? AND password=?", (username,hashed_pw))
        user= self.cursor.fetchone()

        if user:
            self.current_user= user[0]
            self.show_dashboard()

        else:
            messagebox.showerror("Error", "Invalid Username or Password")


    def register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm= self.reg_confirm.get()

        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill all fields")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        try:
            hashed_pw= self.hash_password(password)
            self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))

            self.conn.commit()
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_login_page()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")


    def show_dashboard(self):
        self.clear_window()

        # Top Bar
        top_bar= tk.Frame(self.root, bg="#0f3460", height=60)
        top_bar.pack(fill="x", pady=5)

        tk.Label(top_bar, text="SpendWiz Dashboard", font=("Helvetica",20,"bold"), bg="#0f3460", fg="00d9ff").pack(side="left", padx=20, pady=10)
        logout_btn= tk.Button(top_bar, text="Logout", font=("Helvetica",10), bg="#e94560", fg="ffffff", cursor="hand2",command=self.logout)
        logout_btn.pack(side="right", padx=20, pady=5)

        # Main container
        main_frame= tk.Frame(self.root, bg="#1a1a2e")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Left panel
        left_panel= tk.Frame(main_frame, bg="#16213e", width=300)
        left_panel.pack(side="left", fill="y", padx=(0,10))
        tk.Label(left_panel, text="Add transaction", font=("Helvetica",16,"bold"), bg="#16213e", fg="00d9ff").pack(pady=15)

        # Type
        tk.Label(left_panel, text="Type", font=("Helvetica",10), bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(10,5))
        self.trans_type= ttk.Combobox(left_panel, values=["Income", "Expense"], state="readonly", width=25)
        self.trans_type.pack(padx=20)
        self.trans_type.set("Expense")

        # Category
        tk.Label(left_panel, text="Category", font=("Helvetica",10), bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(10,5))
        self.trans_category = ttk.Combobox(left_panel, values=["Food", "Transport", "Entertainment", "Bills", "Shopping", "Salary", "Other"], state="readonly", width=25)
        self.trans_category.pack(padx=20)
        self.trans_category.set("Food")

        # Amount
        tk.Label(left_panel, text="Amount", font=("Helvetica",10), bg="#16213e", fg="#ffffff").pack(anchor="w",padx=20, pady=(10,5))
        self.trans_amount=tk.Entry(left_panel, font=("Helvetica",12), width=27, bg="#1a1a2e", fg="#ffffff", insertbackground="#ffffff")
        self.trans_amount.pack(padx=20)

        # Description
        tk.Label(left_panel, text="Description", font=("Helvetica",10),bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(10,5))
        self.trans_desc= tk.Entry(left_panel, font=("Helvetica",12), width=27, bg="#1a1a2e", fg="#ffffff", insertbackground="#ffffff")
        self.trans_desc.pack(padx=20)


        # Add button
        add_btn= tk.Button(left_panel, text="Add Transaction", font=("Helvetica",12,"bold"), bg="#00d9ff", fg="#1a1a2e", cursor="hand2", command=self.add_transaction)
        add_btn.pack(pady=20)

        # Right panel
        right_panel=tk.Frame(main_frame, bg="#1a1a2e")
        right_panel.pack(side="right", fill="both", expand=True)

        # Summary cards
        summary_frame= tk.Frame(right_panel, bg="#1a1a2e")
        summary_frame.pack(fill="x", pady=(0,20))

        self.income_label= self.create_summary_card(summary_frame, "Total Income","৳0.00","#4ecdc4")
        self.expense_label= self.create_summary_card(summary_frame, "Total Expenses", "৳0.00", "#e94560")
        self.balance_label= self.create_summary_card(summary_frame, "Balance","৳0.00","#00d9ff")

        # Transaction List
        list_frame= tk.Frame(right_panel, bg="#16213e")
        list_frame.pack(fill="both", expand=True)

        tk.Label(list_frame, text="Recent Transactions", font=("Helvetica",14,"bold"), bg="#16213e", fg="#00d9ff").pack(pady=10)

        # Treeview
        columns= ("Data","Type","Category","Amount","Description")
        self.tree= ttk.Treeview(list_frame, columns=columns, show="headings", height=15)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        scrollbar= ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)

        # Suggestion
        sugg_frame= tk.Frame(right_panel, bg="#16213e", height=100)
        sugg_frame.pack(fill="x", pady=(10,0))

        tk.Label(sugg_frame, text="💡 Smart Suggestions", font=("Helvetica", 12, "bold"), bg="#16213e", fg="#00d9ff").pack(pady=5)
        self.suggestion_label= tk.Label(sugg_frame,text="Add transactions to get suggestions", font=("Helvetica",10), bg="#16213e", fg="#ffffff", wraplength=600, justify="left")
        self.suggestion_label.pack(padx=20, pady=5)

        self.refresh_dashboard()


    def create_summary_card(self, parent, title, value, colour):
        card= tk.Frame(parent, bg=colour, width=200, height=100)
        card.pack(side="left", padx=10, fill="x", expand=True)

        tk.Label(card, text=title, font=("Helvetica",12), bg=colour, fg="#1a1a2e").pack(pady=(15,5))
        value_label= tk.Label(card, text=value, font=("Helvetica",20,"bold"), bg=colour, fg="#1a1a2e")
        value_label.pack()

        return value_label


    def add_transaction(self):
        trans_type= self.trans_type.get()
        category= self.trans_category.get()
        amount= self.trans_amount.get().strip()
        description= self.trans_desc.get().strip()

        if not amount:
            messagebox.showerror("Error", "Please enter an amount")
            return

        if not category:
            messagebox.showerror("Error", "Please enter a category")
            return

        try:
            amount= float(amount)
            if amount <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid positive number")
            return

        date= datetime.now().strftime("%m/%d/%Y")

        self.cursor.execute('''
            INSERT INTO transactions (user_id, type, category, amount, description, date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''',(self.current_user, trans_type, category, amount, description, date))

        self.conn.commit()

        self.trans_amount.delete(0, tk.END)
        self.trans_desc.delete(0, tk.END)

        messagebox.showinfo("Success", "Transaction added successfully!")
        self.refreash_dashboard()




