import math
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict
from tkinter.ttk import Treeview
import random

from unicodedata import category


class ExpenseTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SpendWiz - Personal Expense Tracker")
        self.root.geometry("10000x700")
        self.root.configure(bg="#1a1a2e")
        self.current_user=None
        self.current_username=None
        self.init_database()
        self.show_login_page()

    def init_database(self):
        self.conn= sqlite3.connect("spendwiz.db")
        self.cursor=self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                security_question TEXT,
                security_answer TEXT,
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
        title =tk.Label(frame, text="SpendWiz", font=("Helvetica", 32, "bold"),bg="#1a1a2e", fg="#00d9ff")
        title.pack(pady=20)

        subtitle= tk.Label(frame, text="Your Personal Expense Companion !!!", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff")
        subtitle.pack()

        # Username
        tk.Label(frame, text="Username", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(20,5))
        self.login_username= tk.Entry(frame,font=("Helvetica",14), width=30, bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.login_username.pack(anchor="w",pady=5)

        # Password
        tk.Label(frame,text="Password", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10,5))
        self.login_password= tk.Entry(frame, font=("Helvetica",14), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.login_password.pack(anchor="w",pady=5)

        # Forgot password
        forgot_btn= tk.Button(frame, text="Forgot Password?", font=("Helvetica",9),bg="#1a1a2e", fg="#00d9ff", bd=0, cursor="hand2", activebackground="#1a1a2e", activeforeground="#00d9ff", command=self.show_forgot_password)
        forgot_btn.pack(anchor="e",pady=5)

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
        self.reg_username = tk.Entry(frame, font=("Helvetica", 12), width=30, bg="#16213e", fg="#ffffff",insertbackground="#ffffff")
        self.reg_username.pack(anchor="w", pady=5)

        # Password
        tk.Label(frame, text="Password", font=("Helvetica", 12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_password = tk.Entry(frame, font=("Helvetica", 12), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.reg_password.pack(anchor="w", pady=5)

        # Confirm Password
        tk.Label(frame, text="Confirm Password", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_confirm = tk.Entry(frame, font=("Helvetica",12), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.reg_confirm.pack(anchor="w", pady=5)

        # Security Question
        tk.Label(frame, text="Security Question", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_sec_question=ttk.Combobox(frame, values=[
            "What's your mother's favourite colour?",
            "What was your first pet's name?",
            "What city were you born in?",
            "What's your favourite book?"],
        state="readonly", width=28, font=("Helvetica",11))
        self.reg_sec_question.pack(pady=5)
        self.reg_sec_question.set("What's your mother's favourite colour?")

        # Security Answer
        tk.Label(frame, text="Security Answer", font=("Helvetica", 12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(10, 5))
        self.reg_sec_answer= tk.Entry(frame, font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff", insertbackground="#ffffff")
        self.reg_sec_answer.pack(pady=5)

        # Buttons
        btn_frame= tk.Frame(frame, bg="#1a1a2e")
        btn_frame.pack(pady=20)

        reg_btn = tk.Button(btn_frame, text="Register", font=("Helvetica", 12, "bold"), bg="#00d9ff", fg="#1a1a2e",
                              width=12, cursor="hand2", command=self.register)
        reg_btn.grid(row=0, column=0, pady=5)

        back_btn = tk.Button(btn_frame, text="Back to Login", font=("Helvetica", 12), bg="#0f3460", fg="#ffffff",
                                 width=12, cursor="hand2", command=self.show_login_page)
        back_btn.grid(row=0, column=1, pady=5)


    def show_forgot_password(self):
        self.clear_window()

        frame= tk.Frame(self.root, bg="#1a1a2e")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        title= tk.Label(frame, text="Reset Password", font=("Helvetica",28,"bold"), bg="#1a1a2e", fg="#00d9ff")
        title.pack(pady=20)

        # Username
        tk.Label(frame, text="Username", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(20, 5))
        self.forgot_username= tk.Entry(frame, font=("Helvetica",14), width=30, bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        self.forgot_username.pack(pady=5)

        # Verify Button
        verify_btn= tk.Button(frame, text="Verify Account", font=("Helvetica",12,"bold"), bg="#00d9ff", fg="#1a1a2e", width=25, cursor="hand2", command=self.verify_security_question)
        verify_btn.pack(pady=20)

        # Back Button
        back_btn=tk.Button(frame,text="Back to Login", font=("Helvetica",11), bg="#0f3460", fg="#ffffff", width=25, cursor="hand2", command=self.show_login_page)
        back_btn.pack(pady=10)


    def verify_security_question(self):
        username= self.forgot_username.get().strip()

        if not username:
            messagebox.showerror("Error", "Please enter your username")
            return

        self.cursor.execute("SELECT security_question, security_answer FROM users WHERE username = ?", (username,))
        result= self.cursor.fetchone()

        if not result:
            messagebox.showerror("Error", "Username not found")
            return

        sec_question, sec_answer= result

        self.show_security_answer_page(username, sec_question, sec_answer)


    def show_security_answer_page(self, username, sec_question, sec_answer):
        self.clear_window()

        frame= tk.Frame(self.root, bg="#1a1a2e")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        title= tk.Label(frame, text="Answer Security Question", font=("Helvetica",24,"bold"), bg="#1a1a2e", fg="#00d9ff")
        title.pack(pady=20)

        tk.Label(frame, text=sec_question, font=("Helvetica",12),bg="#1a1a2e",fg="#ffffff", wraplength=400).pack(pady=20)

        tk.Label(frame, text="Your Answer", font=("Helvetica",12),bg="#1a1a2e", fg="#ffffff").pack(anchor="w", pady=(10,5))
        answer_entry=tk.Entry(frame,font=("Helvetica",12), width=30, bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        answer_entry.pack(pady=5)

        def check_answer():
            if answer_entry.get().strip().lower()==sec_answer.lower():
                self.show_reset_password_page(username)

            else:
                messagebox.showerror("Error", "Incorrect answer. Please try again.")

        submit_btn= tk.Button(frame, text="Submit", font=("Helvetica",12,"bold"), bg="#00d9ff", fg="#1a1a2e", width=25, cursor="hand2", command=check_answer)
        submit_btn.pack(pady=20)

        back_btn= tk.Button(frame, text="Back", font=("Helvetica",11), bg="#0f3460", fg="#ffffff", width=25, cursor="hand2", command=self.show_login_page)
        back_btn.pack(pady=10)


    def show_reset_password_page(self, username):
        self.clear_window()

        frame= tk.Frame(self.root, bg="#1a1a2e")
        frame.place(relx=0.5, rely=0.5, anchor="center")

        title= tk.Label(frame, text="Set New Password", font=("Helvetica",28, "bold"), bg="#1a1a2e", fg="#00d9ff")
        title.pack(pady=20)

        # New Password
        tk.Label(frame, text="New Password", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w",pady=(20,5))
        new_pass= tk.Entry(frame, font=("Helvetica",12), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        new_pass.pack(pady=5)

        # Confirm Password
        tk.Label(frame, text="Confirm New Password", font=("Helvetica",12), bg="#1a1a2e", fg="#ffffff").pack(anchor="w", pady=(10,5))
        confirm_pass= tk.Entry(frame, font=("Helvetica",12), width=30, show="*", bg="#16213e", fg="#ffffff", insertbackground="#ffffff")
        confirm_pass.pack(pady=5)
        def reset_password():
            new_password=new_pass.get()
            confirm_password= confirm_pass.get()

            if not new_password or not confirm_password:
                messagebox.showerror("Error", "Please fill all fields")
                return

            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return

            hashed_pw= self.hash_password(new_password)
            self.cursor.execute("UPDATE users SET password=? WHERE username = ?", (hashed_pw, username))
            self.conn.commit()

            messagebox.showinfo("Success", "Password has been reset successfully!")
            self.show_login_page()

        reset_btn= tk.Button(frame, text= "Reset Password", font=("Helvetica",12,"bold"),bg="#00d9ff", fg="#1a1a2e", width=25, cursor="hand2", command=reset_password)
        reset_btn.pack(pady=30)


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
            self.current_username= username
            self.show_dashboard()

        else:
            messagebox.showerror("Error", "Invalid Username or Password")


    def register(self):
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm= self.reg_confirm.get()
        sec_question= self.reg_sec_question.get()
        sec_answer= self.reg_sec_answer.get().strip()


        if not username or not password or not confirm or not sec_answer:
            messagebox.showerror("Error", "Please fill all fields")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return

        try:
            hashed_pw= self.hash_password(password)
            self.cursor.execute("INSERT INTO users (username, password, security_question, security_answer) VALUES (?, ?, ?, ?)", (username, hashed_pw, sec_question, sec_answer))
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

        tk.Label(top_bar, text="SpendWiz Dashboard", font=("Helvetica",20,"bold"), bg="#0f3460", fg="#00d9ff").pack(side="left", padx=20, pady=10)
        btn_frame= tk.Frame(top_bar, bg="#0f3460")
        btn_frame.pack(side="right", padx=20)

        settings_btn= tk.Button(btn_frame, text="⚙️ Settings", font=("Helvetica",10), bg="#16213e",fg="#ffffff",cursor="hand2",command=self.show_settings)
        settings_btn.pack(side="left", padx=5)

        logout_btn= tk.Button(btn_frame, text="Logout", font=("Helvetica",10), bg="#e94560", fg="#ffffff", cursor="hand2",command=self.logout)
        logout_btn.pack(side="left", padx=5)

        # Main container
        main_frame= tk.Frame(self.root, bg="#1a1a2e")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Left panel
        left_panel= tk.Frame(main_frame, bg="#16213e", width=280)
        left_panel.pack(side="left", fill="y", padx=(0,10))
        tk.Label(left_panel, text="Add transaction", font=("Helvetica",16,"bold"), bg="#16213e", fg="#00d9ff").pack(pady=15)

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


        content_frame= tk.Frame(right_panel, bg="#1a1a2e")
        content_frame.pack(fill="both", expand=True)

        # Pie Chart
        chart_frame= tk.Frame(content_frame, bg="#16213e", height=300)
        chart_frame.pack(fill="both", expand=True, pady=(0,10))

        tk.Label(chart_frame, text="📊 Expense Breakdown", font=("Helvetica",14,"bold"),bg="#16213e", fg="#00d9ff").pack(pady=10)
        self.chart_canvas=tk.Canvas(chart_frame, bg="#16213e", width=400, height=250, highlightthickness=0)
        self.chart_canvas.pack(pady=10)

        # Transaction List
        list_frame= tk.Frame(right_panel, bg="#16213e")
        list_frame.pack(fill="both", expand=True)

        tk.Label(list_frame, text="Recent Transactions", font=("Helvetica",14,"bold"), bg="#16213e", fg="#00d9ff").pack(pady=10)

        # Treeview
        columns= ("Date","Type","Category","Amount","Description")
        self.tree= ttk.Treeview(list_frame, columns=columns, show="headings", height=8)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)

        scrollbar= ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y", pady=10)

        # Suggestion
        sugg_frame= tk.Frame(left_panel, bg="#16213e", height=100)
        sugg_frame.pack(fill="x", pady=(20,0))

        tk.Label(sugg_frame, text="💡 Smart Suggestions", font=("Helvetica", 16, "bold"), bg="#16213e", fg="#00d9ff").pack(pady=5)
        self.suggestion_label= tk.Label(sugg_frame,text="Add transactions to get suggestions", font=("Helvetica",14), bg="#16213e", fg="#ffffff", wraplength=250, justify="left")
        self.suggestion_label.pack(padx=20, pady=5)

        self.refresh_dashboard()


    def show_settings(self):
        settings_win= tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("400x700")
        settings_win.configure(bg="#1a1a2e")
        settings_win.transient(self.root)
        settings_win.grab_set()

        tk.Label(settings_win, text="⚙️ Settings", font=("Helvetica",20, "bold"), bg="#1a1a2e", fg="#00d9ff").pack(pady=20)
        tk.Label(settings_win, text=f"Logged in as: {self.current_username}", font=("Helvetica",11),bg="#1a1a2e", fg="#ffffff").pack(pady=10)

        frame= tk.Frame(settings_win, bg="#16213e")
        frame.pack(fill="x", padx=20, pady=20)

        tk.Label(frame, text="Clear All Transactions", font=("Helvetica", 14, "bold"), bg="#16213e", fg="#00d9ff").pack(pady=15)
        clear_btn = tk.Button(frame, text="Clear Transactions", font=("Helvetica", 11, "bold"), bg="#e94560",
                              fg="#ffffff", width=25, cursor="hand2", command=self.clear_transactions)
        clear_btn.pack(pady=5)

        tk.Label(frame,text="Delete Account", font=("helvetica",14,"bold"), bg="#16213e", fg="#00d9ff").pack(pady=15)
        delete_btn=tk.Button(frame, text="Delete My Account", font=("Helvetica", 11, "bold"), bg="#e94560",
                              fg="#ffffff", width=25, cursor="hand2", command=self.delete_account)
        delete_btn.pack(pady=5)

        tk.Label(frame, text="Change Password", font=("Helvetica",14,"bold"), bg="#16213e", fg="#00d9ff").pack(pady=10)
        tk.Label(frame, text="Current Password", font=("Helvetica",10),bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(5,2))
        current_pass= tk.Entry(frame, font=("Helvetica",11), width=25, show="*", bg="#1a1a2e", fg="#ffffff",insertbackground="#ffffff")
        current_pass.pack(padx=20,pady=5)

        tk.Label(frame, text="New Password", font=("Helvetica",10),bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(5,2))
        new_pass= tk.Entry(frame, font=("Helvetica",11), width=25, show="*", bg="#1a1a2e", fg="#ffffff",insertbackground="#ffffff")
        new_pass.pack(padx=20,pady=5)

        tk.Label(frame, text="Confirm New Password", font=("Helvetica",10),bg="#16213e", fg="#ffffff").pack(anchor="w", padx=20, pady=(5,2))
        confirm_pass= tk.Entry(frame, font=("Helvetica",11), width=25, show="*", bg="#1a1a2e", fg="#ffffff",insertbackground="#ffffff")
        confirm_pass.pack(padx=20,pady=5)

        def change_password():
            current=current_pass.get()
            new=new_pass.get()
            confirm=confirm_pass.get()

            if not current or not new or not confirm:
                messagebox.showerror("Error", "Please fill all fields")
                return

            hashed_current= self.hash_password(current)
            self.cursor.execute("SELECT id FROM users WHERE id=? AND password=?",(self.current_user,hashed_current))

            if not self.cursor.fetchone():
                messagebox.showerror("Error", "Current Password is incorrect")
                return

            if new!=confirm:
                messagebox.showerror("Error", "New Passwords do not match")
                return

            if len(new)<8:
                messagebox.showerror("Error", "Password must be at least 8 characters")
                return

            hashed_new= self.hash_password(new)
            self.cursor.execute("UPDATE users SET password=? WHERE id=?",(hashed_new,self.current_user))

            self.conn.commit()

            messagebox.showinfo("Success", "Password has been changed successfully!")
            settings_win.destroy()


        btn_frame= tk.Frame(settings_win, bg="#1a1a2e")
        btn_frame.pack(pady=20)

        change_btn= tk.Button(btn_frame, text="Change Password", font=("Helvetica",11,"bold"), bg="#00d9ff",fg="#1a1a2e", width=15, cursor="hand2", command=change_password)
        change_btn.pack(side="left",padx=5)

        close_btn=tk.Button(btn_frame, text="Close", font=("Helvetica",11), bg="#0f3460", fg="#ffffff",width=10, cursor="hand2", command=settings_win.destroy)
        close_btn.pack(side="left",padx=5)


    def clear_transactions(self):
        confirm=messagebox.askyesno("Confirm", "Are you sure you want to delete all your transactions? This cannot be undone!")
        if confirm:
            self.cursor.execute("DELETE FROM transactions WHERE user_id=?",(self.current_user,))
            self.conn.commit()
            messagebox.showinfo("Success", "Transactions have been deleted successfully!")
            self.refresh_dashboard()


    def delete_account(self):
        confirm=messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This will delete all your transaction and cannot be undone!")
        if confirm:
            self.cursor.execute("DELETE FROM transactions WHERE user_id=?",(self.current_user,))
            self.cursor.execute("DELETE FROM users WHERE id=?",(self.current_user,))
            self.conn.commit()
            messagebox.showinfo("Success", "Your account and all transactions have been deleted successfully!")

            self.current_user=None
            self.current_username=None
            self.show_login_page()



    def create_summary_card(self, parent, title, value, colour):
        card= tk.Frame(parent, bg=colour, width=200, height=100)
        card.pack(side="left", padx=10, fill="x", expand=True)

        tk.Label(card, text=title, font=("Helvetica",12), bg=colour, fg="#1a1a2e").pack(pady=(15,5))
        value_label= tk.Label(card, text=value, font=("Helvetica",20,"bold"), bg=colour, fg="#1a1a2e")
        value_label.pack()

        return value_label


    def draw_pie_chart(self,data):
        self.chart_canvas.delete("all")

        if not data or sum(data.values())==0:
            self.chart_canvas.create_text(250, 125, text="📊 No expense data yet\nAdd transactions to see your spending breakdown", font=("Helvetica",12), fill="#ffffff", justify="center")
            return

        total= sum(data.values())

        colours={
            "Food": "#FF6B6B",
            "Transport": "#4ECDC4",
            "Entertainment": "#FFE66D",
            "Bills": "#A8E6CF",
            "Shopping": "#FF8B94",
            "Salary": "#95E1D3",
            "Other": "#C7CEEA"
        }

        sorted_data=dict(sorted(data.items(), key=lambda item: item[1], reverse=True))

        start_angle=0
        center_x, center_y= 180, 125
        radius=85

        shadow_offset= 3
        for i, (category, amount) in enumerate(sorted_data.items()):
            extent=(amount/total)*360

            self.chart_canvas.create_arc(center_x-radius+shadow_offset,
                                               center_y-radius+shadow_offset,
                                               center_x+radius+shadow_offset,
                                               center_y+radius+shadow_offset,
                                               start= start_angle, extent=extent,
                                               fill="#0a0a0a", outline="", width=0)

            start_angle+=extent

        start_angle=0
        for i,(category, amount) in enumerate(sorted_data.items()):
            extent=(amount/total)*360
            colour=colours.get(category, "#C7CEEA")

            self.chart_canvas.create_arc(center_x-radius,
                                         center_y-radius,
                                         center_x+radius,
                                         center_y+radius,
                                         start= start_angle, extent=extent,
                                         fill=colour,outline="#1a1a2e", width=2
                                         )

            if extent>30:
                angle_mid= start_angle+extent/2
                label_radius=radius*0.65
                label_x=center_x+label_radius*math.cos(math.radians(angle_mid))
                label_y=center_y-label_radius*math.sin(math.radians(angle_mid))

                percentage= (amount/total)*100
                self.chart_canvas.create_text(label_x, label_y,
                                              text=f"{percentage:.0f}%",
                                              font=("Helvetica",10,'bold'),
                                              fill="#1a1a2e")
                start_angle+=extent


            inner_radius=30
            self.chart_canvas.create_oval(center_x-inner_radius,
                                          center_y-inner_radius,
                                          center_x+inner_radius,
                                          center_y+inner_radius,
                                          fill="#16213e",outline="#1a1a2e",width=2)

            self.chart_canvas.create_text(center_x, center_y-5,
                                          text="Total",font=("Helvetica",9),fill="#ffffff")
            self.chart_canvas.create_text(center_x, center_y+10,text=f"৳{total:.0f}", font=("Helvetica",12,"bold"),fill="#00d9ff")


        legend_x=300
        legend_y=20

        for i,(category, amount) in enumerate(sorted_data.items()):
            colour=colours.get(category, "#C7CEEA")
            y_pos=legend_y+i*50

            self.chart_canvas.create_rectangle(legend_x,y_pos,
                                               legend_x+18,y_pos+18,
                                               fill=colour, outline=colour, width=1)
            self.chart_canvas.create_text(legend_x+25, y_pos+4,
                                          text=category,anchor="w", font=("Helvetica",10,'bold'),fill="#ffffff")
            percentage= (amount/total)*100
            self.chart_canvas.create_text(legend_x+25, y_pos+18, text=f"৳{amount:.2f} ({percentage:.1f}%)",anchor="w", font=("Helvetica",9),fill="#cccccc")



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
        self.refresh_dashboard()



    def refresh_dashboard(self):
        self.cursor.execute('''
            SELECT date, type, category, amount, description
            FROM transactions
            WHERE user_id = ?
            ORDER BY date DESC, id DESC
            LIMIT 50
        ''',(self.current_user,))

        transactions= self.cursor.fetchall()

        for item in self.tree.get_children():
            self.tree.delete(item)

        total_income=0
        total_expenses=0
        category_expenses=defaultdict(float)

        for trans in transactions:
            date, trans_type, category, amount, desc=trans
            try:
                amount=float(amount)
            except (TypeError, ValueError):
                amount=0.0
            if trans_type=="Income":
                total_income+=amount
                self.tree.insert("","end",values=(date,trans_type,category,f"৳{amount:.2f}",desc),tags=("income",))

            else:
                total_expenses += amount
                category_expenses[category] += amount
                self.tree.insert("","end",values=(date,trans_type,category,f"৳{amount:.2f}",desc),tags=("expense",))


        self.tree.tag_configure("income", background="#d4edda")
        self.tree.tag_configure("expense", background="#f8d7da")

        balance=total_income-total_expenses

        self.income_label.config(text=f"৳{total_income:.2f}")
        self.expense_label.config(text=f"৳{total_expenses:.2f}")
        self.balance_label.config(text=f"৳{balance:.2f}")

        self.draw_pie_chart(dict(category_expenses))
        self.generate_suggestions(total_income, total_expenses, transactions)


    def generate_suggestions(self, income, expenses, transactions):
        suggestions= []

        if expenses==0 and income==0:
            suggestions.append("| No transaction yet. Start by adding your income and expenses to track your finances!\n")

        if expenses>income:
            suggestions.append("| ⚠️ Your expenses exceed your income! Consider reducing spending.\n")

        category_totals= defaultdict(float)
        for trans in transactions:
            if trans[1]=="Expense":
                try:
                    amount=float(trans[3])
                except (TypeError, ValueError):
                    amount=0.0
                category_totals[trans[2]]+=amount


        if category_totals and expenses>0:
            max_category=max(category_totals, key=category_totals.get)
            if category_totals[max_category]>expenses*0.4:
                suggestions.append(f"| 📊 {max_category} is {category_totals[max_category]/expenses*100:.1f}% of your expenses. Consider budgeting for it.\n")


        if income>0:
            savings_rate=(income-expenses)/income*100
            if savings_rate<20:
                suggestions.append(f"| 💰 Try to save at least 20% of income. Currently: {savings_rate:.1f}%.\n")

        else:
            if expenses>0:
                suggestions.append("| ⚠️ No income recorded but expenses exist- add your income to get accurate suggestions.\n")

        if income >0 and expenses > 0:
            savings_rate=(income-expenses)/income*100
            max_cat_percent=0
            if category_totals:
                max_category=max(category_totals, key=category_totals.get)
                max_cat_percent=(category_totals[max_category]/expenses)*100

            if savings_rate>=20 and max_cat_percent<=40 and expenses<income:
                suggestions.append("| ✅ Great job! Your finances look healthy!!!\n")

        if not suggestions:
            suggestions.append("| ✅ All good - keep tracking your finances!\n")

        self.suggestion_label.config(text="".join(suggestions))



    def logout(self):
        self.current_user = None
        self.current_username = None
        self.show_login_page()


if __name__ == "__main__":
    root= tk.Tk()
    app= ExpenseTrackerApp(root)
    root.mainloop()












