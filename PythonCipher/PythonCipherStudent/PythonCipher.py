#Name: Deaven Kaiser
# Program that similuates encryption for demistration using Caesar Cipher.


def caesar_cipher(message, shift, action):
    result = ""
    
    #Shift calculation
    for char in message:
        if char.isalpha():
            shift_amount = shift % 26  # Ensure shift is within the alphabet
            if action == "encrypt":
                shifted_char = chr(((ord(char) - ord('A' if char.isupper() else 'a') + shift_amount) % 26) + ord('A' if char.isupper() else 'a'))
            elif action == "decrypt":
                shifted_char = chr(((ord(char) - ord('A' if char.isupper() else 'a') - shift_amount) % 26) + ord('A' if char.isupper() else 'a'))
            else:
                return "Invalid action (use 'encrypt' or 'decrypt')"
            result += shifted_char
        else:
            result += char
    
    return result


#Decripts and display 10 possible answers
def decrypt_with_all_shifts():
    ciphertext = entry_message.get("1.0", tk.END)
    possible_messages = []

    for shift in range(26):
        decrypted_message = caesar_cipher(ciphertext, shift, "decrypt")
        possible_messages.append(f"Shift {shift}: {decrypted_message}")

    result_text = "\n".join(possible_messages)
    text_result.delete("1.0", tk.END)
    text_result.insert(tk.END, "Possible Decrypted Messages:\n" + result_text)

def encrypt_message():
    message = entry_message.get("1.0", tk.END)
    shift = int(entry_shift.get())
    action = "encrypt"
    result = caesar_cipher(message, shift, action)
    text_result.delete("1.0", tk.END)
    text_result.insert(tk.END, "Encrypted Message:\n" + result)

# Create the main window
window = tk.Tk()
window.title("Caesar Cipher")

# Message entry
label_message = tk.Label(window, text="Enter the message:")
label_message.pack()
entry_message = scrolledtext.ScrolledText(window, height=5, width=40)
entry_message.pack()

# Shift value entry
label_shift = tk.Label(window, text="Enter the shift value:")
label_shift.pack()
entry_shift = tk.Entry(window)
entry_shift.pack()

# Radio buttons for action
var_action = tk.StringVar(value="encrypt")
label_action = tk.Label(window, text="Select action:")
label_action.pack()
encrypt_radio = tk.Radiobutton(window, text="Encrypt", variable=var_action, value="encrypt")
decrypt_radio = tk.Radiobutton(window, text="Decrypt", variable=var_action, value="decrypt")
encrypt_radio.pack()
decrypt_radio.pack()

# Encrypt/Decrypt buttons
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_message)
encrypt_button.pack()
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_with_all_shifts)
decrypt_button.pack()

# Result text box
text_result = scrolledtext.ScrolledText(window, height=10, width=40)
text_result.pack()

# Start the GUI main loop
