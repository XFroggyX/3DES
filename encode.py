from Crypto.Cipher import DES
import os


# запись в бинарный фаил
def writing_binary_file(file_name, text):
    with open(file_name, "wb") as file:
        file.write(text)


# генерация ключа
def generate_key(file_name) -> bytes:
    key_ = os.urandom(24)
    writing_binary_file(file_name, key_)
    return key_


# генерация iv
def generate_iv(file_name) -> bytes:
    iv = os.urandom(8)
    writing_binary_file(file_name, iv)
    return iv


# возвращает весь бинарный текст из файла
def reading_binary_file(file_name):
    with open(file_name, 'rb') as file:
        text = file.read()
    return text


# проверяем размер кюча
def check_size_key(key_):
    if len(key_) != 24:
        raise ValueError("Invalid triple DES key size. Key must be either 16 or 24 bytes long")
    return 24


# получаем вектро инициализации
def get_vector_iv(file_vec, key_) -> bytes:
    if file_vec:
        iv = reading_binary_file(file_vec)
        if len(iv) != 8:
            raise ValueError("Invalid triple DES iv. Iv must be 8 bytes long")
        return iv
    else:
        return bytes(list(key_)[:8])


# DES encode
def des_encode(key_, mod, text, iv=b""):
    if mod == DES.MODE_ECB:
        cipher = DES.new(key_, mod)
    else:
        cipher = DES.new(key_, mod, iv)
    return cipher.encrypt(text)


# DES decode
def des_decode(key_, mod, text, iv=b""):
    if mod == DES.MODE_ECB:
        cipher = DES.new(key_, mod)
    else:
        cipher = DES.new(key_, mod, iv)
    return cipher.decrypt(text)


# возвращает весь текст из файла
def get_str_from_file(file_name) -> str:
    with open(file_name) as file:
        text = file.read()
    return text


# проверяет размер блока
def check_block(byte_str):
    if len(byte_str) % 8 == 0:
        return byte_str
    block = list(byte_str)
    while len(block) % 8 != 0:
        block.append(0)
    return bytes(block)


# побитовая операция для байт
def byte_xor(ba1, ba2):
    result = []
    list_ba1 = list(ba1)
    list_ba2 = list(ba2)
    for a, b in zip(list_ba1, list_ba2):
        result.append(a ^ b)
    return bytes(result)


# main
def encode(file_text, file_key, file_encode_text, file_vec="", mod="ECB"):
    key_ = reading_binary_file(file_key)
    check_size_key(key_)

    iv = get_vector_iv(file_vec, key_)
    with open(file_text, "r") as f_text:
        with open(file_encode_text, "wb+") as f_encode:
            if mod == "ECB":
                mod_ = DES.MODE_ECB
                while text := f_text.read(8):
                    msg = des_encode(key_[:8], mod_, check_block(text.encode()))
                    msg = des_decode(key_[8:16], mod_, msg)
                    msg = des_encode(key_[16:], mod_, msg)
                    f_encode.write(msg)

            elif mod == "ICBC":
                mod_ = DES.MODE_CBC
                block1 = iv
                block2 = iv
                block3 = iv
                while text := f_text.read(8):
                    msg = byte_xor(block1, check_block(text.encode()))
                    block1 = des_encode(key_[:8], mod_, msg, iv)

                    msg = byte_xor(block2, block1)
                    block2 = des_decode(key_[8:16], mod_, msg, iv)
                    msg = byte_xor(block3, block2)
                    block3 = des_encode(key_[16:], mod_, msg, iv)
                    f_encode.write(block3)

            elif mod == "OCBC":
                mod_ = DES.MODE_CBC
                block = iv
                while text := f_text.read(8):
                    msg = check_block(byte_xor(block, text.encode()))
                    block = des_encode(key_[:8], mod_, msg, iv)
                    block = des_decode(key_[8:16], mod_, block, iv)
                    block = des_encode(key_[16:], mod_, block, iv)
                    f_encode.write(block)

            elif mod == "PAD":
                mod_ = DES.MODE_ECB
                while text := f_text.read(8):
                    msg = des_encode(key_[:8], mod_, check_block(text.encode()))
                    rand = os.urandom(4)
                    msg = rand + msg + rand
                    msg = des_encode(key_[8:16], mod_, msg)
                    rand = os.urandom(4)
                    msg = rand + msg + rand
                    block = des_encode(key_[16:], mod_, msg)
                    f_encode.write(block)

            else:
                f_encode.close()
                raise ValueError("Invalid triple DES mod.")

    return key_


if __name__ == "__main__":
    key = generate_key("key.bin")
    vec = generate_iv("vec.bin")
    print(reading_binary_file("vec.bin"))
    print(encode("text.txt", "key.bin", "encode_text.txt", "vec.bin", "ICBC"))
