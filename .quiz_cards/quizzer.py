import json
import os
import random

FLASHCARD_PATH = os.path.expanduser("~/.quiz_cards/flashcards.json")

def load_flashcards():
    try:
        with open(FLASHCARD_PATH, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"[ERROR] Failed to load flashcards: {e}")
        return []

def ask_random_question():
    cards = load_flashcards()
    if not cards:
        print("[!] No flashcards available.")
        return

    card = random.choice(cards)
    print(f"\nRandom Quiz\nQ: {card['question']}")
    input("Your answer (Enter to reveal): ")
    os.system(f'echo "{card['answer']}" | cowsay')

if __name__ == "__main__":
    ask_random_question()
