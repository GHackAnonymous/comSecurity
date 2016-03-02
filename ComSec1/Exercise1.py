from keyczar import keyczar
from keyczar.errors import KeyczarError


def main():
    try:
        crypter = keyczar.Crypter.Read("./ficheros_clave_primaria_keyczar")
    except KeyczarError as e:
        print("Error reading the key");
    else:
        try:
            msg_file_64 = open("texto_cifrado_paso2_keyzcar.base64", 'r')
        except IOError as e:
            print "Error reading the ciphered text"
        else:
            msg_str_64 = msg_file_64.read()
            msg = crypter.Decrypt(msg_str_64)
            print "Decrypted message " + msg
            try:
                output_file = open("texto_descifrado_paso3_keyczar.base64", 'w+')
            except IOError as e:
                print "Error opening the output file for writting"
            else:
                output_file.write(msg.encode('base64'))
                output_file.close()


if __name__ == '__main__':
    main()
