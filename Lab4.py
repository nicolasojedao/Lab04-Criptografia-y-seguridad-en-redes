from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def ajustarKey(key, length):
    if len(key) < length:
        key += get_random_bytes(length - len(key))
    else:
        key = key[:length]
    return key

def cifrarAES256(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

def descifrarAES256(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def cifrarDES(key, iv, data):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    return ciphertext

def descifrarDES(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return data

def cifrar3DES(key, iv, data):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    return ciphertext

def descifrar3DES(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return data

def main():
    
    choice = input("Eliga uno de los siguientes algoritmos ingresando su número correspondiente: \n 1. AES-256 \n 2. DES \n 3. 3DES \n").strip().upper()
    key = input("\nIngrese su Key: \n").encode('utf-8')
    iv = input("\nIngrese el Vector de Inicialización (debe ser de 16 bytes para AES y 8 bytes para DES/3DES): \n").encode('utf-8')
    data = input("\nIngrese el texto a cifrar: ").encode('utf-8')
    print("\n")
    if choice == "1":

        print("Clave ingresada por el usuario para AES-256:", key)
        key = ajustarKey(key, 32)  
        print("Clave ajustada para AES-256:", key)

        ciphertext = cifrarAES256(key, iv, data)
        print("AES-256 cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrarAES256(key, iv, ciphertext)
        print("AES-256 descifrado:", decrypted_data.decode('utf-8'))

    elif choice == "2":

        print("Clave ingresada por el usuario para DES:", key)
        key = ajustarKey(key, 8)        
        print("Clave ajustada para DES:", key)

        ciphertext = cifrarDES(key, iv, data)
        print("DES cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrarDES(key, iv, ciphertext)
        print("DES descifrado:", decrypted_data.decode('utf-8'))

    elif choice == "3":

        print("Clave ingresada por el usuario para 3DES:", key)
        key = ajustarKey(key, 24)      
        print("Clave ajustada para 3DES:", key)

        ciphertext = cifrar3DES(key, iv, data)
        print("3DES cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrar3DES(key, iv, ciphertext)
        print("3DES descifrado:", decrypted_data.decode('utf-8'))

    else:
        print("El número que ingresó no es una opción válida. Por favor, vuelva a intentarlo")

if __name__ == "__main__":
    main()