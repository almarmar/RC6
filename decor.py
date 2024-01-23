
def key_expansion(key):
    key_size = 16
    expanded_key_size = 44

    # Ensure key is 16 bytes
    key = key[:key_size]

    # Initialize expanded key
    w = [0] * expanded_key_size

    # Copy main key into the first 4 words of the expanded key
    for i in range(key_size // 4):
        w[i] = int.from_bytes(key[i * 4:(i + 1) * 4], 'big')

    # Key expansion
    for i in range(key_size // 4, expanded_key_size):
        t = w[i - 1]
        if i % (key_size // 4) == 0:
            t = (t ^ w[i - key_size // 4]) + (i // (key_size // 4))
        w[i] = t & 0xFFFFFFFF

    return w



def word_addition(a, b, c, t):
    mod = 2**32
    a = (a + b) % mod
    a = (a << 3) | (a >> (32 - 3))
    c = (c << 1) | (c >> (32 - 1))
    return (a + c + t) % mod


def rc6_encrypt(plain_text, key):
    block_size = 16
    key_size = 16

    # Подготовка ключа
    key = bytearray(key, 'utf-8')
    key = key[:key_size]

    # Расширение ключа
    w = key_expansion(key)

    # Подготовка текста
    plain_text = bytearray(plain_text, 'utf-8')
    plain_text += b'\x00' * (block_size - len(plain_text) % block_size)
    num_blocks = len(plain_text) // block_size

    # Шифрование блоков
    encrypted_text = bytearray()
    for i in range(num_blocks):
        block = plain_text[i * block_size:(i + 1) * block_size]
        A, B, C, D = block_addition(block)

        # Итерации шифрования
        B = (B + w[0]) & 0xFFFFFFFF
        D = (D + w[1]) & 0xFFFFFFFF
        for round in range(1, 21):
            t = (B * (2 * B + 1)) & 0xFFFFFFFF
            u = (D * (2 * D + 1)) & 0xFFFFFFFF

            A = (rotate_left(A ^ t, u) + w[2 * round]) & 0xFFFFFFFF
            C = (rotate_left(C ^ u, t) + w[2 * round + 1]) & 0xFFFFFFFF

            A, B, C, D = B, C, D, A

        A = (A + w[42]) & 0xFFFFFFFF
        C = (C + w[43]) & 0xFFFFFFFF

        encrypted_text += int.to_bytes(A, 4, 'big') + int.to_bytes(B, 4, 'big') + \
                          int.to_bytes(C, 4, 'big') + int.to_bytes(D, 4, 'big')

    return encrypted_text

def rc6_decrypt(cipher_text, key):
    block_size = 16
    key_size = 16

    # Подготовка ключа
    key = bytearray(key, 'utf-8')
    key = key[:key_size]

    # Расширение ключа
    w = key_expansion(key)

    # Подготовка текста
    num_blocks = len(cipher_text) // block_size

    # Дешифрование блоков
    decrypted_text = bytearray()
    for i in range(num_blocks):
        block = cipher_text[i * block_size:(i + 1) * block_size]
        A, B, C, D = block_addition(block)

        # Итерации дешифрования
        C = (C - w[43]) & 0xFFFFFFFF
        A = (A - w[42]) & 0xFFFFFFFF
        for round in range(20, 0, -1):
            A, B, C, D = D, A, B, C

            t = (B * (2 * B + 1)) & 0xFFFFFFFF
            u = (D * (2 * D + 1)) & 0xFFFFFFFF

            C = (rotate_right(C - w[2 * round + 1], t)) & 0xFFFFFFFF
            A = (rotate_right(A - w[2 * round], u)) & 0xFFFFFFFF

        D = (D - w[1]) & 0xFFFFFFFF
        B = (B - w[0]) & 0xFFFFFFFF

        decrypted_text += int.to_bytes(A, 4, 'big') + int.to_bytes(B, 4, 'big') + \
                          int.to_bytes(C, 4, 'big') + int.to_bytes(D, 4, 'big')

    return decrypted_text.rstrip(b'\x00')


def block_addition(block):
    return int.from_bytes(block[0:4], 'big'), int.from_bytes(block[4:8], 'big'), \
           int.from_bytes(block[8:12], 'big'), int.from_bytes(block[12:16], 'big')


def rotate_left(value, shift):
    shift %= 32  # Убедимся, что shift в пределах от 0 до 31
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def rotate_right(value, shift):
    shift %= 32  # Убедимся, что shift в пределах от 0 до 31
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF






