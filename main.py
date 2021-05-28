import sys
import getopt
import os
import OpenSSL.crypto as crypto

# default type is RSA
KEY_TYPE = crypto.TYPE_RSA

CA_CERT_INFO = {
    "C": "DE",
    "ST": "Bayern",
    "L": "Uni Passau",
    "O": " ",
    "OU": " ",
    "CN": ""
}


def create_key_pair(key_type, key_name):
    commands_to_exec = []
    bit_size = 2048
    curve = "prime256v1"

    if key_type == "RSA" or key_type == "DSA":
        bit_size = define_key_size()
    else:
        curve = define_curve()

    if key_type == "RSA":
        commands_to_exec.append("openssl genrsa -out {}.pem {}".format(key_name, bit_size))
    elif key_type == "DSA":
        commands_to_exec.append("openssl dsaparam -out {}.pem -genkey {}".format(key_name, bit_size))
    elif key_type == "ECDSA":
        commands_to_exec.append("openssl ecparam -genkey -out {}.pem -name {}".format(key_name, curve))
    elif key_type == "ECDH":
        commands_to_exec.append("openssl ecparam -out ecparam.pem -name {}".format(curve))
        commands_to_exec.append("openssl genpkey -paramfile ecparam.pem -out {}.pem".format(key_name))
    else:
        print("Error! Invalid key type")
        return
    execute_commands(commands_to_exec)


def create_ca_signed_certificate(path_to_key, cert_name, ca_key, ca_cert, valid_days=365):
    commands_to_exec = ["openssl req -new -out {}.csr -key {}".format(cert_name, path_to_key),
                        "openssl x509 -req -in {}.csr -CA {} -CAkey {} -CAcreateserial -out {}.crt -days {}"
                        .format(cert_name, ca_cert, ca_key, cert_name, valid_days)]
    execute_commands(commands_to_exec)


def create_ca_certificate(path_to_key, cert_name, valid_days=365):
    command = "openssl req -new -x509 -days {} -key {} -out {}.crt"\
        .format(valid_days, path_to_key, cert_name)
    os.system(command)


def execute_commands(command_list):
    for command in command_list:
        os.system(command)


def setup_ca():
    create_key_pair(KEY_TYPE, "ca")
    create_ca_certificate("ca.pem", "ca")
    return True


def setup_sever():
    create_key_pair(KEY_TYPE, "server")
    create_ca_signed_certificate("server.pem", "server", "ca.pem", "ca.crt")
    return True


def setup_client():
    create_key_pair(KEY_TYPE, "client")
    create_ca_signed_certificate("client.pem", "client", "ca.pem", "ca.crt")
    return True


def interactive_setup():
    print("Interactive Setup for Self Signed Certificate Generation")
    print("[1] CA Setup")
    print("Do you already have a CA and want to use it? (y/n)")
    if binary_question():
        print("Not implemented yet, sawry")
        return
    else:
        clear_console()
        print("-------- CA Setup --------")
        define_key_type()
        print("-------- Define certificate information --------")
        if setup_ca():
            print("Successfully setup ca key and certificate")
        else:
            print("Error! Failed setting up CA")
            return

    clear_console()

    print("-------- Setup Server/Broker --------")
    if setup_sever():
        print("Successfully setup broker key and certificate")
    else:
        print("Error! Failed setting up broker certs")
        return

    clear_console()

    print("-------- Setup Client --------")
    if setup_client():
        print("Successfully setup client key and certificate")
    else:
        print("Error! Failed setting up client certs")


def binary_question():
    input_string = input()
    if input_string is None:
        return True
    elif "n" in input_string:
        return False

    return True


def clear_console():
    command = 'clear'
    if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
        command = 'cls'
    os.system(command)


def define_key_type():
    global KEY_TYPE
    print("Which key type should be used? Possible options are:\n(1) RSA\n(2) ECDSA\n(3) DSA\n(4) ECDH")
    number = input("Select a number: ")

    if number == "1":
        KEY_TYPE = "RSA"
    elif number == "2":
        KEY_TYPE = "ECDSA"
    elif number == "3":
        KEY_TYPE = "DSA"
    elif number == "4":
        KEY_TYPE = "ECDH"
    else:
        print("Error! Invalid input. Try again")
        define_key_type()

    print("{} set successfully as key type".format(str(KEY_TYPE)))


def define_key_size():
    print("Which bit size should the key have?")
    print("Possible options are:\n(1) 2048 (default)\n(2) 4096")
    selection = input("Select one or press enter to use default: ")
    bit_size = 2048

    if selection == 2:
        bit_size = 4096

    return bit_size


def define_curve():
    print("Enter the curve that should be used")
    print("(To see a list of possible values, run 'openssl list_curves')")
    curve = input()

    if curve == "":
        curve = "prime256v1"
        print(curve)
    # TODO check if given curve is valid
    return curve


def common_name_input(message=""):
    string = input(message)
    if string == "" or string == " ":
        print("Input must not be empty, try again!")
        common_name_input()
    return string


def usage():
    print("------------------- FANCY NAME -------------------")
    print("Script parameters are given below. If none are given, the script is started in interactive mode")
    print("-k: Key type of the generated keys")


if __name__ == '__main__':
    if not len(sys.argv[1:]):
        interactive_setup()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "keytype:o:h")
    except getopt.GetoptError as err:
        print(err)
        usage()

    for o, a in opts:

        if o in "-keytype":
            if len(a):
                start_addr = a

            if len(args):
                end_addr = args[0]

        elif o in "-os":
            if len(a):
                pass

        elif o in "-h":
            usage()

        else:
            print("Error invalid input!")
            usage()

