from encode import reading_binary_file, check_size_key, get_vector_iv, des_encode, des_decode, check_block, byte_xor
from Crypto.Cipher import DES


# запись в фаил
def writing_file(file_name, text):
    with open(file_name, "w") as file:
        file.write(text)


# удаление не значимых нулей
def del_zero(bin_str):
    list_bin = list(bin_str)
    if len(list_bin) <= 0:
        return bin_str
    if list_bin[-1] != 0:
        return bin_str
    while list_bin[-1] == 0:
        del list_bin[-1]
    return bytes(list_bin)


# преобразует список байтовых сток в декодированную строку
def byte_list_to_str(bytes_list):
    str_ = ""
    for i in range(len(bytes_list)):
        str_ += del_zero(bytes_list[i]).decode()
    return str_


# main
def decode(file_encode, file_key, file_vec, mod, file_text):
    key = reading_binary_file(file_key)
    check_size_key(key)

    iv = get_vector_iv(file_vec, key)

    encode_text = reading_binary_file(file_encode)

    if mod == "ECB":
        mod_ = DES.MODE_ECB
        result = []
        i = 0
        while i < len(encode_text):
            msg = des_decode(key[16:], mod_, encode_text[i:i + 8])
            msg = des_encode(key[8:16], mod_, msg)
            msg = des_decode(key[:8], mod_, msg)
            result.append(msg)
            i += 8

        str_ = ""
        for i in range(len(result)):
            str_ += del_zero(result[i]).decode()

        writing_file(file_text, str_)
        return str_
    elif mod == "ICBC":
        mod_ = DES.MODE_CBC
        result = []
        i = 0
        msg1 = iv
        msg2 = iv
        msg3 = iv
        while i < len(encode_text):
            msg = check_block(encode_text[i:i + 8])

            block = des_decode(key[16:], mod_, msg, iv)
            swap = byte_xor(block, msg1)
            msg1 = msg

            msg = swap
            block = des_encode(key[8:16], mod_, msg, iv)
            swap = byte_xor(block, msg2)
            msg2 = msg

            msg = swap

            block = des_decode(key[:8], mod_, msg, iv)
            swap = byte_xor(block, msg3)
            msg3 = msg

            result.append(swap)
            i += 8

        str_ = byte_list_to_str(result)
        writing_file(file_text, str_)
        return str_
    elif mod == "OCBC":
        mod_ = DES.MODE_CBC
        result = []
        i = 0
        swap = iv
        while i < len(encode_text):
            msg = check_block(encode_text[i:i + 8])
            block = des_decode(key[16:], mod_, msg, iv)
            block = des_encode(key[8:16], mod_, block, iv)
            block = des_decode(key[:8], mod_, block, iv)
            block = del_zero(block)
            block = byte_xor(block, swap)
            swap = msg
            result.append(block)
            i += 8

        str_ = byte_list_to_str(result)
        writing_file(file_text, str_)
        return str_
    elif mod == "PAD":
        mod_ = DES.MODE_ECB
        result = []
        i = 0
        while i < len(encode_text):
            msg = des_decode(key[16:], mod_, check_block(encode_text[i:i + 24]))
            msg = msg[4:len(msg) - 4]
            msg = des_decode(key[8:16], mod_, msg)
            msg = msg[4:len(msg) - 4]
            block = des_decode(key[:8], mod_, msg)

            result.append(block)
            i += 24

        str_ = byte_list_to_str(result)
        writing_file(file_text, str_)
        return str_
    else:
        raise ValueError("Invalid triple DES mod.")


if __name__ == "__main__":
    print(decode("encode_text.txt", "key.bin", "vec.bin", "ICBC", "dectext.txt"))
