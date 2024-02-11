Enigma Password Manager (EPW)

The Enigma Password Manager (EPW) is a Python-based application designed to help users securely manage their passwords. It offers features for user registration, login, password storage, retrieval, and management.

Key Components:

User Registration:

Users can register with a unique username and a master password.
The master password is hashed using SHA-256 before storage to enhance security.
User registration is a one-time process, ensuring that only one user can exist at a time.
User Login:

Registered users can log in using their username and master password.
The login process validates the entered credentials against the stored username and hashed master password.
Users have a maximum number of login attempts, providing security against brute-force attacks.
Password Management:

Once logged in, users can perform various password management tasks.
They can add new passwords for different websites along with their corresponding usernames.
Passwords are encrypted using the Fernet symmetric encryption algorithm, enhancing confidentiality.
Users can retrieve saved passwords for websites they have previously added.
The application allows users to change passwords for existing website entries, providing flexibility and security.
View Saved Websites:

Users can view a list of websites for which they have saved passwords.
This feature provides users with an overview of their password-protected accounts.
User Interface (UI):

The application's user interface is built using PySimpleGUI, a Python library for creating graphical user interfaces.
It offers intuitive windows and buttons for navigation and interaction, enhancing user experience.
Security Measures:

Hashing and Encryption:

User passwords are hashed using the SHA-256 algorithm before storage, preventing unauthorized access to sensitive information.
Passwords stored in the application are encrypted using the Fernet symmetric encryption algorithm, ensuring confidentiality.
Maximum Login Attempts:

To mitigate the risk of brute-force attacks, users have a limited number of login attempts before being locked out of the system temporarily.
File Storage:

User Data Storage:

User registration information, including usernames and hashed master passwords, is stored in a JSON file (user_data.json).
Passwords for different websites, along with their corresponding usernames, are stored in another JSON file (passwords.json).
Encryption Key Generation:

An encryption key is generated using the Fernet algorithm and stored in a file (encryption_key.key) to facilitate password encryption and decryption.
Usage:

Registration and Login:

Users can register for an account using a unique username and master password.
After registration, users can log in using their credentials to access password management features.
Password Management:

Users can add, retrieve, and change passwords for different websites.
Passwords are stored securely and can be accessed only after successful authentication.
Viewing Saved Websites:

Users can view a list of websites for which they have saved passwords, providing them with visibility into their password-protected accounts.
Conclusion:

The Enigma Password Manager (EPW) provides users with a secure and convenient solution for managing their passwords.
By leveraging hashing, encryption, and user authentication mechanisms, it ensures the confidentiality and integrity of user data.
With its intuitive user interface and robust security features, EPW offers users a reliable tool for password management in today's digital world.
