def circular_left_shift(value, shift):
    return ((value << shift) & 0xFFFFFFFFFFFFFFFF) | ((value >> (64 - shift)) & 0xFFFFFFFFFFFFFFFF)


def generate_sub_keys(key):
    sub_keys = []
    key = int.from_bytes(key, 'big')

    # Split the 128-bit key into two 64-bit halves
    left_half = key >> 64
    right_half = key & 0xFFFFFFFFFFFFFFFF

    # Perform 16 rounds of circular left shift and XOR
    for i in range(16):
        left_half = circular_left_shift(left_half, 1)
        right_half = circular_left_shift(right_half, 1)

        sub_key = (((left_half << 64) & 0xFFFFFFFFFFFFFFFF) | right_half)
        sub_keys.append(int.to_bytes(sub_key, 8, 'big'))

    return sub_keys


def s_box(byte):
    # A simple S-box as an example (should be more complex in practice)
    return byte ^ 0xA5


def feistel_round(left, right, sub_key):
    # Convert sub key to an integer
    sub_key_int = int.from_bytes(sub_key, 'big')
    # XOR operation
    new_right = left ^ sub_key_int
    # Apply S-box
    new_right = s_box(new_right)
    # New left half is the same as previous right half
    new_left = right
    return new_left, new_right


def encrypt(plain_text, key):
    # Convert plaintext to two 32-bit halves
    left = int.from_bytes(plain_text[:4], 'big')
    right = int.from_bytes(plain_text[4:], 'big')

    # Generate sub_keys
    sub_keys = generate_sub_keys(key)

    # Execute 16 rounds of the Feistel algorithm
    for sub_key in sub_keys:
        left, right = feistel_round(left, right, sub_key)

    # Combine halves and return encrypted text
    encrypted_text = ((left << 32) & 0xFFFFFFFF) | right
    return encrypted_text.to_bytes(8, 'big')


# Example of usage:
encrypted_bytes = encrypt(
    plain_text=b'example1',   # 64 bits
    key=b'secret_key123456',  # 128 bits
)
print("Encrypted text:", encrypted_bytes)
