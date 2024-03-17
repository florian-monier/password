import re
import tkinter as tk
from tkinter import messagebox
import hashlib
import json
import os
import random
import string


def check_password():
    password = entry.get()
    if len(password) < 8:
        messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins 8 caractères.")
    elif not re.search("[A-Z]", password):
        messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins une lettre majuscule.")
    elif not re.search("[a-z]", password):
        messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins une lettre minuscule.")
    elif not re.search("[0-9]", password):
        messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins un chiffre.")
    elif not re.search("[!@#$%^&*]", password):
        messagebox.showerror("Erreur", "Le mot de passe doit contenir au moins un caractère spécial ( ! , @, #, $, %, ^, & , *).")
    else:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if os.path.exists('passwords.json'):
            with open('passwords.json', 'r') as file:
                passwords = json.load(file)
                if hashed_password in passwords:
                    messagebox.showerror("Erreur", "Ce mot de passe a déjà été utilisé.")
                else:
                    passwords.append(hashed_password)
                    with open('passwords.json', 'w') as file:
                        json.dump(passwords, file)
                    messagebox.showinfo("Succès", "Le mot de passe est valide et a été enregistré.")
        else:
            with open('passwords.json', 'w') as file:
                json.dump([hashed_password], file)
            messagebox.showinfo("Succès", "Le mot de passe est valide et a été enregistré.")


def generate_password():
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(random.choice(characters) for _ in range(8))
    entry.delete(0, tk.END)
    entry.insert(0, password)

root = tk.Tk()
root.title("Gestionnaire de mots de passe")

label = tk.Label(root, text="Entrez votre mot de passe:")
label.pack()

entry = tk.Entry(root)
entry.pack()

check_button = tk.Button(root, text="Vérifier le mot de passe", command=check_password)
check_button.pack()

generate_button = tk.Button(root, text="Générer un mot de passe aléatoire", command=generate_password)
generate_button.pack()

root.mainloop()
