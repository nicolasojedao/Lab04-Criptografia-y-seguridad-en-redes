from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def ajustar_clave(key, longitud_requerida):
    if len(key) < longitud_requerida:
        key += get_random_bytes(longitud_requerida - len(key))
    else:
        key = key[:longitud_requerida]
    return key

def cifrar_AES256(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

def descifrar_AES256(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return data

def cifrar_DES(key, iv, data):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    return ciphertext

def descifrar_DES(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return data

def cifrar_3DES(key, iv, data):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    return ciphertext

def descifrar_3DES(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return data

def main():
    
    algoritmo = input("Eliga uno de los siguientes algoritmos ingresando su número correspondiente: \n 1. AES-256 \n 2. DES \n 3. 3DES \n").strip().upper()
    key = input("Ingrese su Key: \n").encode('utf-8')
    iv = input("Ingrese el Vector de Inicialización (debe ser de 16 bytes para AES y 8 bytes para DES/3DES): \n").encode('utf-8')
    data = input("Ingrese el texto a cifrar: ").encode('utf-8')

    
    if algoritmo == "1":
        key = ajustar_clave(key, 32)  
        iv = ajustar_clave(iv, 16)    
        print("Clave ajustada para AES-256:", key)

        
        ciphertext = cifrar_AES256(key, iv, data)
        print("AES Cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrar_AES256(key, iv, ciphertext)
        print("AES Descifrado:", decrypted_data.decode('utf-8'))

    elif algoritmo == "2":
        key = ajustar_clave(key, 8)   
        iv = ajustar_clave(iv, 8)     
        print("Clave ajustada para DES:", key)

        
        ciphertext = cifrar_DES(key, iv, data)
        print("DES Cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrar_DES(key, iv, ciphertext)
        print("DES Descifrado:", decrypted_data.decode('utf-8'))

    elif algoritmo == "3":
        key = ajustar_clave(key, 24)  
        iv = ajustar_clave(iv, 8)    
        print("Clave ajustada para 3DES:", key)

        
        ciphertext = cifrar_3DES(key, iv, data)
        print("3DES Cifrado en Base64:", base64.b64encode(ciphertext).decode('utf-8'))
        decrypted_data = descifrar_3DES(key, iv, ciphertext)
        print("3DES Descifrado:", decrypted_data.decode('utf-8'))

    else:
        print("El número que ingresó no es una opción válida. Por favor, vuelva a intentarlo")

if __name__ == "__main__":
    main()