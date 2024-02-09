import PySimpleGUI as sg
import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet


# Function for Hashing the Master Password.
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()


# Generate a secret key. This should be done only once as you'll see.
def generate_key():
    return Fernet.generate_key()


# Initialize Fernet cipher with the provided key.
def initialize_cipher(key):
    return Fernet(key)


# Function to encrypt a  password.
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()


# Function to decrypt a  password.
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()


# Function to register you.
def register(username, master_password):
    # Encrypt the master password before storing it
    hashed_master_password = hash_password(master_password)
    user_data = {'username': username, 'master_password': hashed_master_password}
    file_name = 'user_data.json'

    if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")


# Function to log you in.
def login(username, entered_password):
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)

        stored_password_hash = user_data.get('master_password')
        entered_password_hash = hash_password(entered_password)

        if entered_password_hash == stored_password_hash and username == user_data.get('username'):
            print("\n[+] Login Successful..\n")
        else:
            print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
            sys.exit()

    except Exception:
        print("\n[-] You have not registered. Please do that.\n")
        sys.exit()


# Function to view saved websites.
def view_websites():
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            websites = [x['website'] for x in view]
            return websites
    except FileNotFoundError:
        return []


# Load or generate the encryption key.
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)


# Function to add (save password).
def add_password(website, password):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        # If passwords.json doesn't exist, initialize it with an empty list
        data = []
    else:
        # Load existing data from passwords.json
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            # Handle the case where passwords.json is empty or invalid JSON.
            data = []

    # Encrypt the password
    encrypted_password = encrypt_password(cipher, password)

    # Create a dictionary to store the website and password
    password_entry = {'website': website, 'password': encrypted_password}
    data.append(password_entry)

    # Save the updated list back to passwords.json
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)


# Function to retrieve a saved password.
def get_password(website):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        return None

    # Load existing data from passwords.json
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    # Loop through all the websites and check if the requested website exists.
    for entry in data:
        if entry['website'] == website:
            # Decrypt and return the password
            decrypted_password = decrypt_password(cipher, entry['password'])
            return decrypted_password

    return None

# Function to change a saved password.
def change_password(website, new_password):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        print("\n[-] You have not saved any passwords!\n")
        return

    # Load existing data from passwords.json
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []

    password_found = False
    # Loop through all the websites and check if the requested website exists.
    for entry in data:
        if entry['website'] == website:
            # Encrypt the new password
            encrypted_new_password = encrypt_password(cipher, new_password)
            # Update the password
            entry['password'] = encrypted_new_password
            password_found = True
            break

    if password_found:
        # Save the updated list back to passwords.json
        with open('passwords.json', 'w') as file:
            json.dump(data, file, indent=4)
        print("\n[+] Password updated successfully!\n")
    else:
        print("\n[-] Password not found! Did you save the password?\n"
              "[-] Use option 3 to see the websites you saved.\n")



layout = [[sg.Text("Enigma Password Manager")], [sg.Button("Register")], [sg.Button("Log-In")], [sg.Button("Quit")]]

# Create home window
home_window = sg.Window("EPW", layout)

## Functions for PySimpleGUI windows
def create_register_window():
    layout = [
        [sg.Text("Register below: *Case Sensitive*")],
        [sg.Text("Username"), sg.InputText(key='-REGISTER_USERNAME-')],
        [sg.Text("Password"), sg.InputText(key='-MASTER_PASSWORD-', password_char='*')],
        [sg.Button("Register")],
        [sg.Button("Cancel")]
    ]
    return sg.Window("Register", layout)


def create_registration_error_window():
    layout = [
        [sg.Text("Master user already exists, please login.")],
        [sg.Button("Exit")]
    ]
    return sg.Window("Error", layout)


def create_login_window():
    layout = [
        [sg.Text("Log in below: *Case Sensitive*")],
        [sg.Text("Username:"), sg.InputText(key='-USERNAME-')],
        [sg.Text("Master Key:"), sg.InputText(key='-PASSWORD-', password_char='*')],
        [sg.Button("Log-In")],
        [sg.Button("Cancel")]
    ]
    return sg.Window("Log-In", layout)


def create_welcome_window():
    layout = [
        [sg.Text(f"Welcome, {username}!!")],
        [sg.Button("1. Add Password")],
        [sg.Button("2. Get Password")],
        [sg.Button("3. Change Saved Password")],
        [sg.Button("4. View Saved Websites")],
        [sg.Button("5. Exit")]
    ]
    return sg.Window("Welcome", layout)


def add_password_window():
    layout = [
        [sg.Text("Add New Password")],
        [sg.Text("Website Username"), sg.InputText(key='-WEBSITE_USERNAME-')],
        [sg.Text("New Password"), sg.InputText(key='-NEW_PASSWORD-', password_char='*')],
        [sg.Button("Save")]
    ]
    return sg.Window("Add Password", layout)


def get_password_window():
    layout = [
        [sg.Text("Get Password")],
        [sg.Text("Website"), sg.InputText(key='-WEBSITE-')],
        [sg.Button("Get Password")]
    ]
    return sg.Window("Get Password", layout)


def change_password_window():
    layout = [
        [sg.Text("Change Saved Password")],
        [sg.Text("Website"), sg.InputText(key='-WEBSITE-')],
        [sg.Button("Search")]
    ]
    return sg.Window("Change Saved Password", layout)


def view_websites_window():
    websites = view_websites()
    layout = [
        [sg.Text("Saved Websites:")],
        [sg.Listbox(values=websites, size=(40, 10))],
        [sg.Button("Close")]
    ]
    return sg.Window("View Saved Websites", layout)





# Event Loop
#*** Home window is open ***#
while True:
    event, values = home_window.read()
    # End program if user closes window or presses quit
    if event == "Quit" or event == sg.WIN_CLOSED:
        break

    elif event == "Register":
        file = 'user_data.json'
        if os.path.exists(file) and os.path.getsize(file) != 0:
            # Opens an error window if a master user already exists
            registration_error_window = create_registration_error_window()
            while True:
                event, values = registration_error_window.read()
                if event == sg.WIN_CLOSED or event == "Exit":
                    registration_error_window.close()
                    break
        else:
            # If no master user exists, close home page, then open registration window
            home_window.close()
            register_window = create_register_window()
        #*** Registration Window is Open ***#
        while True:
            event, values = register_window.read()
            if event == "Cancel" or sg.WIN_CLOSED:
                register_window.close()
                break
            elif event =="Register":
                username = values['-REGISTER_USERNAME-']
                master_password = values['-MASTER_PASSWORD-']
                register(username, master_password)


    elif event == "Log-In":
        login_window = create_login_window()
        while True:
            event, values = login_window.read()
            if event == sg.WIN_CLOSED:
                break
            elif event == "Cancel":
                login_window.close()
                break
            elif event == "Log-In":
                username = values['-USERNAME-']
                entered_password = values['-PASSWORD-']
                login(username, entered_password)
                login_window.close()
                welcome_window = create_welcome_window()

                #***Display the welcome window***#

                while True:
                    event, values = welcome_window.read()
                    if event == "1. Add Password":
                        add_password_win = add_password_window()
                        while True:
                            event, values = add_password_win.read()
                            if event == sg.WIN_CLOSED:
                                break
                            if event == "Save":
                                website_username = values['-WEBSITE_USERNAME-']
                                new_password = values['-NEW_PASSWORD-']
                                add_password(website_username, new_password)
                                sg.popup("New password saved successfully!")
                        add_password_win.close()
                        break

                    elif event == "2. Get Password":
                        get_password_win = get_password_window()
                        while True:
                            event, values = get_password_win.read()
                            if event == sg.WIN_CLOSED:
                                break
                            if event == "Get Password":
                                website = values['-WEBSITE-']
                                password = get_password(website)
                                if password:
                                    sg.popup(
                                        f"Password for {website}:\n{password}\n\nThe password has been copied to your clipboard.")
                                    pyperclip.copy(password)
                                else:
                                    sg.popup(f"No password found for {website}.")
                                get_password_win.close()


                    elif event == "3. Change Saved Password":
                        # Change Saved Password functionality
                        change_password_win = change_password_window()
                        while True:
                            event, values = change_password_win.read()
                            if event == "Search":
                                website = values['-WEBSITE-']
                                if get_password(website):
                                    new_password_layout = [
                                        [sg.Text(f"Change password for {website}")],
                                        [sg.Text("New Password"), sg.InputText(key='-NEW_PASSWORD-')],
                                        [sg.Button("Save Password")]
                                    ]
                                    new_password_win = sg.Window("Change Password", new_password_layout)
                                    while True:
                                        event, values = new_password_win.read()
                                        if event == "Save Password":
                                            new_password = values['-NEW_PASSWORD-']
                                            change_password(website, new_password)
                                            sg.popup(f"Password for {website} updated!")
                                            new_password_win.close()
                                            break
                                else:
                                    sg.popup(f"No password found for {website}.")
                            elif event == sg.WIN_CLOSED:
                                change_password_win.close()
                                break


                    elif event == "4. View Saved Websites":
                        # View Saved Websites functionality
                        view_websites_win = view_websites_window()
                        while True:
                            event, values = view_websites_win.read()
                            if event == sg.WIN_CLOSED:
                                break
                            if event == "Close":
                                view_websites_win.close()
                                break

                    elif event == sg.WIN_CLOSED or event == "5. Exit":
                        welcome_window.close()
                        home_window.close()
                        break
                    # Handle other events in the welcome window as needed

home_window.close()