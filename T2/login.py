#Very cool login and register page - All passwords saved on a txt file, hashed and with some salt on top 
#Handles log in and registering of new users
#Has cool error messages when something goes wrong
#Could use some visual pzaz but we'll get to that later
#Thanks chatGPT uwu

import hashlib
import tkinter as tk
from tkinter import messagebox
import os
import binascii

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    hashed_password = binascii.hexlify(key).decode()
    return f"{salt.hex()}:{hashed_password}"

def check_password(username, password):
    with open("passwords.txt") as f:
        for line in f:
            u, hashed_password = line.strip().split(":", 1)
            if u == username:
                salt, password_hash = hashed_password.split(":")
                salt = bytes.fromhex(salt)
                if hash_password(password, salt) == hashed_password:
                    return True
                else:
                    return False
    return False



def register():
    # Create a new window for the register form
    register_window = tk.Toplevel()
    register_window.title("Register")

    # Add a label for the username
    username_label = tk.Label(register_window, text="Username:")
    username_label.grid(row=0, column=0, pady=5)

    # Add an entry for the username
    username_entry = tk.Entry(register_window)
    username_entry.grid(row=0, column=1, pady=5)

    # Add a label for the password
    password_label = tk.Label(register_window, text="Password:")
    password_label.grid(row=1, column=0, pady=5)

    # Add an entry for the password
    password_entry = tk.Entry(register_window, show="*")
    password_entry.grid(row=1, column=1, pady=5)

    # Add a button for registering
    register_button = tk.Button(register_window, text="Register", command=lambda: save_user(username_entry.get(), password_entry.get(), register_window))
    register_button.grid(row=2, columnspan=2, pady=5)

def save_user(username, password, register_window):
    hashed_password = hash_password(password)

    # Save the username and hashed password to the users file
    with open("passwords.txt", "a") as f:
        f.write(f"{username}:{hashed_password}\n")

    # Show a success message
    tk.messagebox.showinfo("Success", "User registered successfully")

    # Close the register window
    register_window.destroy()


def loginPage():
    login = tk.Tk()
    #login.geometry("400x400")
    login.title("Login Page")

    logged_user = tk.StringVar()

    label1 = tk.Label(login, text="Username")
    label2 = tk.Label(login, text="Password")

    entry1 = tk.Entry(login, textvariable=logged_user)
    entry2 = tk.Entry(login, show="*")

   
    label1.grid(row=0, column=0, sticky="E")
    label2.grid(row=1, column=0, sticky="E")
    entry1.grid(row=0, column=1)
    entry2.grid(row=1, column=1)
 

    def verify():   ##This is where the user is validated
        with open("passwords.txt") as f:
            for line in f:
                username, hashed_password = line.strip().split(":", 1)
                if username == entry1.get():   
                    if check_password(username, entry2.get()):
                        login.destroy()
                        return 
                    else:
                        messagebox.showerror("Error", "Incorrect username or password")
                        return
                
            messagebox.showerror("Error", "Username not found")
                

    buttonLogin = tk.Button(login, text="Login", command=verify)
    buttonRegister = tk.Button(login, text="Register", command= register)
    buttonLogin.grid(columnspan=2)
    buttonRegister.grid(columnspan=4)



    login.mainloop()
    return logged_user.get()
    

