import sys
import getopt
import os
import OpenSSL.crypto as crypto
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

# default type is RSA
KEY_TYPE = crypto.TYPE_RSA

CA_KEY = None
CA_CERT = None
CLIENT_KEY = None
CLIENT_CERT = None
SERVER_CERT = None
SERVER_KEY = None

CLIENT_CERT_INFO = {
    "C": "DE",
    "ST": "Bayern",
    "L": "Passau",
    "OU": "",
    "CN": ""
}

SERVER_CERT_INFO = {
    "C": "DE",
    "ST": "Bayern",
    "L": "Uni Passau",
    "OU": "",
    "CN": ""
}

CA_CERT_INFO = {
    "C": "DE",
    "ST": "Bayern",
    "L": "Uni Passau",
    "O": " ",
    "OU": " ",
    "CN": ""
}


def create_key_pair_new(key_type, key_name):
    commands_to_exec = []
    bit_size = 2048
    curve = ""

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


def create_key_pair(key_type, bit_size=2048, key_curve=ec.SECP224R1()):
    key = None
    if key_type == crypto.TYPE_RSA:
        key = crypto.PKey()
        key.generate_key(key_type, bits=bit_size)
    elif key_type == crypto.TYPE_EC:
        ec_key = ec.generate_private_key(key_curve, default_backend())
        key_pem = ec_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                       encryption_algorithm=NoEncryption())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

    return key


def create_cert_signing_request(entity_key, cert_info):
    csr = crypto.X509Req()

    try:
        csr.get_subject().C = cert_info['C']
        csr.get_subject().ST = cert_info['ST']
        csr.get_subject().L = cert_info['L']
        csr.get_subject().O = cert_info['O']
        csr.get_subject().OU = cert_info['OU']
        csr.get_subject().CN = cert_info['CN']
        csr.set_pubkey(entity_key)
    except crypto.Error:
        print("Failed creating certificate signing request. There is probably an issue with the given information")

    return csr


def create_self_signed_cert(signing_key, request, signing_cert=None):
    cert = crypto.X509()

    if signing_cert is None:
        signing_cert = cert

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60 * 100)
    cert.set_subject(request.get_subject())
    cert.set_issuer(signing_cert.get_subject())
    cert.set_pubkey(request.get_pubkey())
    cert.sign(signing_key, "sha256")
    return cert


def setup_ca():
    global CA_CERT, CA_KEY, CA_CERT_INFO
    key_size = define_key_size()
    try:
        CA_CERT_INFO = collect_csr_information("CA")
        CA_KEY = create_key_pair(KEY_TYPE, key_size)
        ca_csr = create_cert_signing_request(CA_KEY, CA_CERT_INFO)
        CA_CERT = create_self_signed_cert(CA_KEY, ca_csr)
    except Exception as err:
        print(err)
        return False
    return True


def setup_sever():
    global SERVER_KEY, SERVER_CERT, SERVER_CERT_INFO
    key_size = define_key_size()

    try:
        SERVER_CERT_INFO = collect_csr_information("Broker")
        SERVER_KEY = create_key_pair(KEY_TYPE, key_size)
        server_csr = create_cert_signing_request(SERVER_KEY, SERVER_CERT_INFO)
        SERVER_CERT = create_self_signed_cert(CA_KEY, server_csr, signing_cert=CA_CERT)
    except Exception as err:
        print(err)
        return False
    return True


def setup_client():
    global CLIENT_KEY, CLIENT_CERT, CLIENT_CERT_INFO
    key_size = define_key_size()

    try:
        CLIENT_CERT_INFO = collect_csr_information("Client")
        CLIENT_KEY = create_key_pair(KEY_TYPE, key_size)
        client_csr = create_cert_signing_request(CLIENT_KEY, CLIENT_CERT_INFO)
        CLIENT_CERT = create_self_signed_cert(CA_KEY, client_csr, signing_cert=CA_CERT)
    except Exception as err:
        print(err)
        return False
    return True


def interactive_setup():
    global CA_CERT_INFO, CLIENT_CERT_INFO, SERVER_CERT_INFO
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
            save_key_file(CA_KEY, "ca")
            save_cert_file(CA_CERT, "ca")
        else:
            print("Error! Failed setting up CA")
            return

    clear_console()

    print("-------- Setup Server/Broker --------")
    if setup_sever():
        print("Successfully setup broker key and certificate")
        save_key_file(SERVER_KEY, "server")
        save_cert_file(SERVER_CERT, "server")
    else:
        print("Error! Failed setting up broker certs")
        return

    clear_console()

    print("-------- Setup Client --------")
    if setup_client():
        print("Successfully setup client key and certificate")
        save_key_file(CLIENT_KEY, "client")
        save_cert_file(CLIENT_CERT, "client")
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
    print("Which key type should be used? Possible options are:\n(1) RSA\n(2) EC\n(3) DSA")
    number = input("Select a number: ")

    if number == "1":
        KEY_TYPE = crypto.TYPE_RSA
    elif number == "2":
        KEY_TYPE = crypto.TYPE_EC
    elif number == "3":
        KEY_TYPE = crypto.TYPE_DSA
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

    # TODO check if given curve is valid
    return curve


def collect_csr_information(entity_name):
    print("Define {} Certificate information:".format(entity_name))
    country_name = input("Country Name (2 letter code): ")
    state = input("State or Province: ")
    city = input("Locality name: ")
    organisation = input("Organization: ")
    org_unit = input("Organizational Unit: ")
    common_name = common_name_input("Common Name (Has to be ip address or FQDN): ")

    csr_info = {
        "C": country_name,
        "ST": state,
        "L": city,
        "O": organisation,
        "OU": org_unit,
        "CN": common_name
    }
    return csr_info


def common_name_input(message=""):
    string = input(message)
    if string == "" or string == " ":
        print("Input must not be empty, try again!")
        common_name_input()
    return string


def save_key_file(key, file_name, ending="pem"):
    if key is not None:
        raw_string = str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        formatted_key = raw_string.replace("\\n", "\n")[2:len(raw_string) - 2]
        with open("{}.{}".format(file_name, ending), "wt") as f:
            f.write(formatted_key)
        return True
    return False


def save_cert_file(cert, file_name):
    if cert is not None and file_name is not None:
        raw_string = str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        formatted_cert = raw_string.replace("\\n", "\n")[2:len(raw_string) - 2]
        with open("{}.crt".format(file_name), "wt") as f:
            f.write(formatted_cert)
        return True
    return False


def usage():
    print("------------------- FANCY NAME -------------------")
    print("Script parameters are given below. If none are given, the script is started in interactive mode")
    print("-k: Key type of the generated keys")


if __name__ == '__main__':
    if not len(sys.argv[1:]):
        interactive_setup()
        # create_cert_signing_request("test", CA_CERT_INFO)

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

