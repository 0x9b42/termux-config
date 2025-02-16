import os
import random
import time
import shutil

def get_terminal_size():
    return shutil.get_terminal_size((80, 24))

# Characters for the matrix effect
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*()"

def matrix_rain():
    rows, cols = get_terminal_size()
    columns = [0] * cols  # Track position of drops
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        
        for i in range(cols):
            if random.random() < 0.02:  # Randomly start new drops
                columns[i] = 0
            
            if columns[i] < rows:
                columns[i] += 1
        
        # Print matrix effect
        for y in range(rows):
            line = ''.join(random.choice(CHARS) if columns[x] > y else ' ' for x in range(cols))
            print(line)
        
        time.sleep(0.05)

if __name__ == "__main__":
    try:
        matrix_rain()
    except KeyboardInterrupt:
        print("\nExiting...")

