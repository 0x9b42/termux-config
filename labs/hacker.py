import random
import time
import shutil
import os

def generate_noise_line(length):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()_+-=<>?/"
    return ''.join(random.choice(chars) for _ in range(length))

def reveal_message(secret_message, speed=0.05):
    rows, columns = shutil.get_terminal_size()
    secret_length = len(secret_message)
    start_col = (columns - secret_length) // 2  # Center the message
    
    for i in range(secret_length + 1):
        os.system('clear' if os.name == 'posix' else 'cls')
        
        for _ in range(rows // 2):
            print(generate_noise_line(columns))
        
        revealed = secret_message[:i] + generate_noise_line(secret_length - i)
        print(" " * start_col + revealed)  # Center message
        
        for _ in range(rows // 2 - 1):
            print(generate_noise_line(columns))
        
        time.sleep(speed)
    
    time.sleep(1)
    print("\n" * 2 + " " * start_col + secret_message)
    time.sleep(2)

if __name__ == "__main__":
    secret = "HELLO, WORLD!"  # Change this to any message you want
    reveal_message(secret)

