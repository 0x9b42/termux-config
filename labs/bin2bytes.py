def binary_to_chunks(input_file, output_file, chunk_size=16):
    with open(input_file, "rb") as f:
        binary_data = f.read()

    # Split the binary data into chunks
    chunks = [binary_data[i : i + chunk_size] for i in range(0, len(binary_data), chunk_size)]

    # Create Python-formatted output
    with open(output_file, "w") as f:
        f.write("binary_data = b''\n")  # Start with an empty byte string
        for chunk in chunks:
            f.write(f"binary_data += {repr(chunk)}\n")

    print(f"Chunked byte string saved to {output_file}")

# Example usage
binary_to_chunks("a.out", "output.py")
