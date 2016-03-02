import nacl.secret
import nacl.public
import nacl.utils


def decode_input_message():
    input_key_file = open('texto_descifrado_paso3_keyczar.base64')
    input_key = input_key_file.read()
    input_key_decoded = input_key.decode('base64')
    return input_key_decoded


def decrypt_symmetric(key):
    input_msg_file = open('texto_cifrado_paso2_nacl.base64', 'r')
    input_msg_encoded = input_msg_file.read()
    input_msg = input_msg_encoded.decode('base64')
    box = nacl.secret.SecretBox(key)
    output_msg = box.decrypt(input_msg)
    print 'Decoded: ', output_msg
    return output_msg


def encrypt_asymmetric(message):
    student_private_key_file = open('skAlumno.base64')
    student_private_key_encoded = student_private_key_file.read()
    student_private_key_decoded = student_private_key_encoded.decode('base64')
    student_private_key = nacl.public.PrivateKey(student_private_key_decoded)

    tutor_public_key_file = open('pkTutor.base64')
    tutor_public_key_encoded = tutor_public_key_file.read()
    tutor_public_key_decoded = tutor_public_key_encoded.decode('base64')
    tutor_public_key = nacl.public.PublicKey(tutor_public_key_decoded)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    student_box = nacl.public.Box(student_private_key, tutor_public_key)
    output_msg = student_box.encrypt(message, nonce)
    return output_msg


def save_output_file(message, file_name):
    message_encoded = str(message).encode('base64')
    message_file = open(file_name, 'w+')
    message_file.write(message_encoded)
    message_file.close()


def main():
    try:
        message = decode_input_message()
    except IOError:
        print "Error reading the input key"
    else:
        try:
            input_msg = decrypt_symmetric(message)
        except IOError:
            print "Error reading the input file"
        else:
            output_msg = encrypt_asymmetric(input_msg)
            try:
                save_output_file(output_msg, 'texto_cifrado_paso_3_nacl.base64')
            except IOError:
                print "Error saving the output file"

if __name__ == '__main__':
    main()
