def rot(text, shift):
    result = []
    for char in text:
        if 'A' <= char <= 'Z':  # Huruf kapital
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif 'a' <= char <= 'z':  # Huruf kecil
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:  # Karakter lain tetap
            result.append(char)
    return ''.join(result)

def convert_all_rots(text):
    for i in range(1, 26):
        print(f"ROT{i}: {rot(text, i)}")

if __name__ == "__main__":
    text = input("Masukkan teks: ")
    convert_all_rots(text)
