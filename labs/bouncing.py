import os
import random
import time
import shutil

# Colors for the DVD logo
def random_color():
    return f'\033[{random.choice(range(31, 37))}m'

# Get terminal size
def get_terminal_size():
    return shutil.get_terminal_size((80, 24))

def dvd_bounce():
    rows, cols = get_terminal_size()
    x, y = random.randint(1, cols - 5), random.randint(1, rows - 2)
    dx, dy = 1, 1  # Direction
    logo = "DVD"
    clear = '\033[H\033[J'

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print(clear)
        print(f'\033[{y};{x}H{random_color()}{logo}\033[0m')
        
        x += dx
        y += dy

        if x <= 1 or x >= cols - len(logo) - 1:
            dx *= -1  # Reverse X direction
        if y <= 1 or y >= rows - 1:
            dy *= -1  # Reverse Y direction

        time.sleep(0.05)

if __name__ == "__main__":
    try:
        dvd_bounce()
    except KeyboardInterrupt:
        print("\nExiting...")

