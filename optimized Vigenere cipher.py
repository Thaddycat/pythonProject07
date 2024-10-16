encrypted_texts = []
key_list = []
current_key_index = 0

def vigenere_sq():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    square = [[alphabet[(i + j) % len(alphabet)] for j in range(len(alphabet))] for i in range(len(alphabet))]
    header = "|   | " + " | ".join(alphabet) + " |"
    print(header)
    print("|---" + "|---" * len(alphabet) + "|")
    for i, row in enumerate(square):
        print(f"| {alphabet[i]} | " + " | ".join(row) + " | ")

def letter_to_index(letter, alphabet):
    return alphabet.index(letter)

def index_to_letter(index, alphabet):
    return alphabet[index]

def vigenere_index(key_letter, plaintext_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    plaintext_index = letter_to_index(plaintext_letter, alphabet)
    ciphertext_index = (plaintext_index + key_index) % len(alphabet)
    return index_to_letter(ciphertext_index, alphabet)

def encrypt_vigenere(key, plaintext, alphabet):
    encrypted_text = []
    key_length = len(key)
    for i, letter in enumerate(plaintext):
        if letter in alphabet:
            key_index = i % key_length
            key_letter = key[key_index]
            encrypted_text_letter = vigenere_index(key_letter, letter, alphabet)
            encrypted_text.append(encrypted_text_letter)
        else:
            encrypted_text.append(letter)
    return ''.join(encrypted_text)

def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    cipher_index = letter_to_index(cipher_letter, alphabet)
    plaintext_index = (cipher_index - key_index) % len(alphabet)
    return index_to_letter(plaintext_index, alphabet)

def decrypt_vigenere(key, cipher_text, alphabet):
    decrypted_text = []
    key_length = len(key)
    for i, letter in enumerate(cipher_text):
        if letter in alphabet:
            key_index = i % key_length
            key_letter = key[key_index]
            plaintext_letter = undo_vigenere_index(key_letter, letter, alphabet)
            decrypted_text.append(plaintext_letter)
        else:
            decrypted_text.append(letter)
    return ''.join(decrypted_text)

def encryption():
    if not key_list:
        print("Must input keys first.")
        return
    plaintext = input("Enter plaintext: ").upper()
    for key in key_list:
        encrypted_message = encrypt_vigenere(key, plaintext, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        encrypted_texts.append(encrypted_message)
        print(f"Encrypted Message with key '{key}': {encrypted_message}")

def decryption():
    if not key_list:
        print("Must input keys first.")
        return
    if not encrypted_texts:
        print("No encrypted texts available for decryption.")
        return
    for i, cipher_text in enumerate(encrypted_texts):
        print(f"\nDecrypting Message {i + 1}: {cipher_text}")
        for key in key_list:
            decrypted_message = decrypt_vigenere(key, cipher_text, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            print(f"Using key '{key}' -> Decrypted Message: {decrypted_message}")

def dump_encrypted_texts():
    print("Encrypted Texts:")
    for i, text in enumerate(encrypted_texts):
        print(f"{i + 1}: {text}")

def input_keys():
    global key_list, current_key_index
    keys = input("Enter keys separated by commas: ").upper().split(',')
    valid_keys = [key.strip() for key in keys
        if key.strip() and all('A' <= char <= 'Z' for char in key.strip())]
    if not valid_keys:
        print("No valid keys entered. Please enter keys consisting of letters only.")
        return
    key_list = valid_keys
    current_key_index = 0
    print("Keys loaded into rotation:", key_list)

def quit_program():
    print("Exiting the program.")
    vigenere_sq()
    print("Session has Terminated.")

def vig_app():
    menu_options = [["Input Keys", input_keys], ["Encrypt", encryption], ["Decrypt", decryption],
                    ["Dump Encrypted Text", dump_encrypted_texts],["Quit", quit_program]]
    while True:
            print("\nMenu:")
            for i, (option, _) in enumerate(menu_options):
                print(f"{i + 1}. {option}")

            try:
                choice = int(input("Select an option (1-5): ")) - 1
                if 0 <= choice < len(menu_options):
                    menu_options[choice][1]()
                    if choice == 4:
                        break
                else:
                    print("Invalid option. Please select again.")
            except (ValueError, IndexError):
                print("Invalid input. Please enter a number between 1 and 5.")
            except KeyboardInterrupt:
                print("\nProgram interrupted. Exiting...")
                vigenere_sq()
                quit_program()
                break

vig_app()