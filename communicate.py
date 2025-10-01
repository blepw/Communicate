from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from colorama import Fore
import binascii
import base64
import os
import sys

# Colors
red = Fore.RED
blue = Fore.BLUE
white = Fore.WHITE
green = Fore.GREEN
magenta = Fore.MAGENTA
reset = Fore.RESET

# AES-256 Key (32 bytes exactly)
KEY = b""


def banner():
    print(f"""{white}[ ================== [AES-256 CBC Mode Encryption Script] ================= ] {reset}""")


def encrypt_text():
    print(f"{blue}[{white}*{blue}] {white}Enter text to encrypt {magenta}(Press Ctrl+C to return to menu) {reset}")
    try:
        while True:
            plaintext = input(f"{blue}[{white}*{blue}] {white}text > ").strip()
            if not plaintext:
                print(f"{white}[{red}!{white}] Empty input, try again {reset}")
                continue
            iv = os.urandom(16)
            cipher = AES.new(KEY, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
            encrypted_data = iv + ciphertext
            b64encoded = base64.b64encode(encrypted_data).decode()
            print(f"{blue}[{white}*{blue}] {white}Encrypted (Base64): {magenta}{b64encoded}\n")
    except KeyboardInterrupt:
        print(f"{blue}[{green}!{blue}]{reset} Returning to main menu...\n")


def decrypt_text():
    print(f"{blue}[{white}*{blue}] {white}Enter Base64 ciphertext to decrypt {magenta}(Press Ctrl+C to return to menu) {reset}")
    try:
        while True:
            # b64_input = input("> ").strip()
            b64_input = input(f"{blue}[{white}*{blue}] {white}base64 encrypted text > ").strip()

            if not b64_input:
                print(f"{white}[{red}!{white}] Empty input, try again {reset}")
                continue

            print(f"\nBase64 input: {b64_input}")  

            try:
                data = base64.b64decode(b64_input)
                iv = data[:16]
                ciphertext = data[16:]
                cipher = AES.new(KEY, AES.MODE_CBC, iv)
                plaintext_padded = cipher.decrypt(ciphertext)
                plaintext = unpad(plaintext_padded, AES.block_size).decode()
                print(f"Decrypted text: {plaintext}\n")

            except (ValueError, KeyError, binascii.Error) as e:
                print(f"{white}[{red}!{white}]  Error decrypting input: {e}\nTry again or Ctrl+C to return.")
    except KeyboardInterrupt:
        print(f"{blue}[{green}!{blue}]{reset} Returning to main menu...\n")


def encrypt_file():
    print(f"\n[!] Enter filename to encrypt {magenta}(pdf or txt, from project folder)")
    try:
        filename = input(f"{blue}[{white}*{blue}] {white}pdf or txt file name > {reset}").strip()
        if not os.path.isfile(filename):
            print(f"{white}[{red}!{white}] {red}File {magenta}'{filename}'{reset} {red}not found in project directory {reset}")
            return

        with open(filename, 'rb') as f:
            data = f.read()

        iv = os.urandom(16)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        output_file = filename + ".enc"

        with open(output_file, 'wb') as f:
            f.write(iv + encrypted)

        print(f"{blue}[{green}*{blue}]{green}File encrypted successfully {magenta}→{reset} {white}{output_file}{reset}\n")
    except KeyboardInterrupt:
        print(f"{blue}[{green}!{blue}]{reset} Returning to main menu...\n")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def decrypt_file():
    print(f"\n [!] Enter filename to decrypt {magenta}(.enc file, from project folder)")
    try:
        filename = input(f"{blue}[{white}*{blue}] {white}.enc file name > {reset}").strip()
        if not os.path.isfile(filename):
            print(f"{white}[{red}!{white}] {red}File {magenta}'{filename}'{reset} {red}not found in project directory {reset}")
            return

        with open(filename, 'rb') as f:
            file_data = f.read()

        iv = file_data[:16]
        ciphertext = file_data[16:]

        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size)

        output_file = f"decrypted_{os.path.basename(filename).replace('.enc', '')}"
        with open(output_file, 'wb') as f:
            f.write(decrypted)
        print(f"{blue}[{green}*{blue}]{green}File decrypted successfully {magenta}→{reset} {white}{output_file}{reset}\n")

    except KeyboardInterrupt:
        print(f"\n{blue}[{green}!{blue}]{reset} Returning to main menu...\n")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def instructions():
    print(f"""{green}
────────────────────────────────────────────────────────────────────────────
  🔐 AES-256 CBC Mode Encryption Tool – Help & Documentation
────────────────────────────────────────────────────────────────────────────

📝 DESCRIPTION:
This tool provides secure AES-256 encryption and decryption for text and files
(.pdf and .txt) using CBC (Cipher Block Chaining) mode. It uses a secure,
hardcoded 32-byte key and a random IV for every encryption operation.

────────────────────────────────────────────────────────────────────────────
📋 OPTIONS & HOW THEY WORK:

[1] Encrypt Text
  - Input plaintext you wish to encrypt.
  - It uses AES-256-CBC with a random IV.
  - Output is shown as a Base64-encoded string.
  - Useful for short secrets, messages, and credentials.

[2] Decrypt Text (Base64)
  - Input a Base64 string that was encrypted with this tool.
  - Automatically extracts the IV and decrypts it.
  - Output is the original human-readable plaintext.

[3] Encrypt File (pdf or txt)
  - Input the filename (must be in the same folder as this script).
  - Reads and encrypts the file content (binary).
  - Saves as `<filename>.enc`, combining IV + encrypted content.

[4] Decrypt File (.enc)
  - Input the filename of a `.enc` encrypted file.
  - Extracts IV, decrypts the file.
  - Saves the result as `decrypted_<originalfilename>`.

[5] Help
  - Shows this help message.

[6] Exit
  - Safely exits the program.

────────────────────────────────────────────────────────────────────────────
🔐 SECURITY NOTE:


AES-256 refers to the key size in bits: 256 bits.

1 byte = 8 bits, so:
32 byte (our key) * 8 = 256 bit 

This encryption, when used correctly, is considered **military-grade** secure.

────────────────────────────────────────────────────────────────────────────

⚠️ REQUIREMENTS:
- Input files must exist in the same directory as this script.
- Encrypted files must not be modified outside this tool.

────────────────────────────────────────────────────────────────────────────
⚠️ SHARING THE KEY SECURELY 

You can utilize platforms such as pastebin to send the key to another user 

- PASTEBIN 

- Create a new paste with the following rules 
[1] Category non 
[2] Tags non 
[3] Paste expiration date : 10 minutes to 1 hour 

This way the paste will be deleted after the other user has received the 32 bit key
for this script 

- Sending the link (example)
Entire link : https://pastebin.com/cDUk44dn 
Path / Resource Identifier :  cDUk44dn

Send the user the resource identifier in plain text through another platform 

────────────────────────────────────────────────────────────────────────────

{reset}""")


def main_menu():
    while True:
        banner()
        print("")
        print(f"{blue}[{white}1{blue}] {reset} Encrypt Text")
        print(f"{blue}[{white}2{blue}] {reset} Decrypt Text (Base64)")
        print(f"{blue}[{white}3{blue}] {reset} Encrypt File (pdf or txt)")
        print(f"{blue}[{white}4{blue}] {reset} Decrypt File (.enc)")
        print(f"{blue}[{white}5{blue}] {reset} Help")
        print(f"{blue}[{white}6{blue}] {reset} Exit \n")
        try:
            choice = input(f"{blue}[{white}*{blue}] {reset}Option {white}> {reset}").strip()

            if choice == "1":
                encrypt_text()
            elif choice == "2":
                decrypt_text()
            elif choice == "3":
                encrypt_file()
            elif choice == "4":
                decrypt_file()
            elif choice == "5":
                instructions()
            elif choice == "6":
                print(f"{green}[*] {reset}Goodbye.")
                sys.exit(0)
            else:
                print(f"{white}[{red}!{white}] {red}Invalid option, try again.\n")
        except KeyboardInterrupt:
            print(f"\n{blue}[{green}!{blue}]{reset} Returning to main menu...\n")


main_menu()
