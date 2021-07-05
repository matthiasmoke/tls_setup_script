import sys
import os
import subprocess
import argparse

# default type is RSA
KEY_TYPE = "RSA"
DESTINATION_FOLDER = os.path.abspath(os.path.join(os.getcwd(), "output"))
CA_KEY_PATH = os.path.join(DESTINATION_FOLDER, "ca.pem")
CA_CERT_PATH = os.path.join(DESTINATION_FOLDER, "ca.crt")


def print_banner():
    print(".___________. __          _______.    _______   __       _______..______    _______ .__   __.      _______. _______ .______      ")
    print("|           ||  |        /       |   |       \ |  |     /       ||   _  \  |   ____||  \ |  |     /       ||   ____||   _  \\")
    print("`---|  |----`|  |       |   (----`   |  .--.  ||  |    |   (----`|  |_)  | |  |__   |   \|  |    |   (----`|  |__   |  |_)  |")
    print("    |  |     |  |        \   \       |  |  |  ||  |     \   \    |   ___/  |   __|  |  . `  |     \   \    |   __|  |      /  ")
    print("    |  |     |  `----.----)   |      |  '--'  ||  | .----)   |   |  |      |  |____ |  |\   | .----)   |   |  |____ |  |\  \----.")
    print("    |__|     |_______|_______/       |_______/ |__| |_______/    | _|      |_______||__| \__| |_______/    |_______|| _| `._____|")


def create_key_pair(key_type, key_name):
    commands_to_exec = []
    bit_size = 2048
    curve = "prime256v1"
    output_file = os.path.abspath(os.path.join(DESTINATION_FOLDER, "{}.pem".format(key_name)))

    if key_type == "RSA" or key_type == "DSA":
        bit_size = define_key_size()
    else:
        curve = define_curve()

    try:
        if key_type == "RSA":
            commands_to_exec.append("openssl genpkey -out {} -algorithm RSA -pkeyopt rsa_keygen_bits:{}"
                                    .format(output_file, bit_size))
        elif key_type == "DSA":
            commands_to_exec.append("openssl dsaparam -out {} -genkey {}".format(output_file, bit_size))
        elif key_type == "EC":
            commands_to_exec.append("openssl ecparam -genkey -out {} -name {}".format(output_file, curve))
        elif key_type == "ECDH":
            commands_to_exec.append("openssl ecparam -out ecparam.pem -name {}".format(curve))
            commands_to_exec.append("openssl genpkey -paramfile ecparam.pem -out {}".format(output_file))
        else:
            print("Error! Invalid key type")
            return False
        execute_commands(commands_to_exec)
    except Exception as error:
        print("There was an error while creating the key pair")
        print(error)
        return False
    return True


def create_ca_signed_certificate(path_to_key, cert_name, path_to_ca_key, path_to_ca_cert, config_file=None, extension_name=None):
    config_param = ""
    extension_param = ""
    if config_file is not None:
        config_param = "-config {}".format(config_file)

        if extension_name is not None:
            extension_param = "-extensions {} -extfile {}".format(extension_name, config_file)

    output_file_csr = os.path.abspath(os.path.join(DESTINATION_FOLDER, "{}.csr".format(cert_name)))
    output_file_crt = os.path.abspath(os.path.join(DESTINATION_FOLDER, "{}.crt".format(cert_name)))

    try:
        commands_to_exec = ["openssl req -new -out {} -key {} {}".format(output_file_csr, path_to_key, config_param),
                            "openssl x509 -req -in {} -CA {} -CAkey {} -CAcreateserial -out {} {}"
                            .format(output_file_csr, path_to_ca_cert, path_to_ca_key, output_file_crt, extension_param)]
        execute_commands(commands_to_exec)
    except Exception as error:
        print("There was an error while creating the certificate")
        print(error)
        return False
    return True


def create_ca_certificate(path_to_key, cert_name, valid_days=365):
    output_file_crt = os.path.abspath(os.path.join(DESTINATION_FOLDER, "{}.crt".format(cert_name)))

    try:
        command = "openssl req -new -x509 -days {} -key {} -config ca.conf -extensions ca_ext -out {}"\
            .format(valid_days, path_to_key, output_file_crt)
        os.system(command)
    except Exception as error:
        print("There was an error while creating the certificate")
        print(error)
        return False
    return True


def get_fingerprint(cert_path):
    command = "openssl x509 -noout -in {} -fingerprint".format(cert_path)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0]
    return str(output)


def execute_commands(command_list):
    for command in command_list:
        os.system(command)


def setup_ca():
    global CA_KEY_PATH, CA_CERT_PATH
    print("-------- Setup Certificate Authority --------")
    define_key_type()
    key_path = os.path.join(DESTINATION_FOLDER, "ca.pem")
    if create_key_pair(KEY_TYPE, "ca"):
        print("For more detailed parameter specification (i.e. req_extensions), have a look at the openssl configuration files.")
        create_ca_certificate(key_path, "ca")

        CA_KEY_PATH = key_path
        CA_CERT_PATH = os.path.join(DESTINATION_FOLDER, "ca.crt")


def setup_sever():
    print("-------- Setup Server/Broker --------")
    define_key_type()
    key_path = os.path.join(DESTINATION_FOLDER, "server.pem")
    if create_key_pair(KEY_TYPE, "server"):
        create_ca_signed_certificate(key_path, "server", CA_KEY_PATH, CA_CERT_PATH, config_file="server.conf", extension_name="server_ext")

        print("Do you want to save the fingerprint of the server certificate? (y/n)")
        if binary_question():
            finger_print = get_fingerprint(os.path.join(DESTINATION_FOLDER, "server.crt"))
            save_to_file(finger_print, "server_fingerprint")


def setup_client():
    print("-------- Setup Client --------")
    define_key_type()
    key_path = os.path.join(DESTINATION_FOLDER, "client.pem")
    if create_key_pair(KEY_TYPE, "client"):
        create_ca_signed_certificate(key_path, "client", CA_KEY_PATH, CA_CERT_PATH, config_file="client.conf", extension_name="client_ext")


def cleanup():
    """
    Remove files that were created in the setup and are not needed anymore (.csr, .srl)
    :return:
    """
    print("Cleaning up files")
    for file in os.listdir(DESTINATION_FOLDER):
        if file.endswith(".csr") or file.endswith(".srl"):
            remove_file(os.path.abspath(os.path.join(DESTINATION_FOLDER, file)))
            print("Deleted {}".format(file))


def init():
    if os.path.exists(DESTINATION_FOLDER) is False:
        os.mkdir(DESTINATION_FOLDER)


def check_ca_paths():
    if not os.path.exists(CA_KEY_PATH):
        raise AttributeError("Specified path to CA key is invalid!")
    elif not os.path.exists(CA_CERT_PATH):
        raise AttributeError("Specified path to CA cert is invalid!")


def interactive_setup():
    print("Interactive Setup for Self Signed Certificate Generation")
    print("This script can also be run with parameters. Use '-h' for more information")
    setup_ca()
    clear_console()
    setup_sever()
    clear_console()
    setup_client()
    cleanup()


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


def remove_file(file_path):
    command = "rm {}".format(file_path)
    if os.name in ('nt', 'dos'):
        command = "del {}".format(file_path)

    os.system(command)


def save_to_file(content, name, ending="txt"):
    destination = os.path.abspath(os.path.join(DESTINATION_FOLDER, "{}.{}".format(name, ending)))
    with open(destination, "w") as f:
        f.write(content)
        f.close()


def define_key_type():
    global KEY_TYPE
    print("Which key type should be used? Possible options are:\n(1) RSA\n(2) EC\n(3) DSA\n(4) ECDH")
    number = input("Select a number: ")

    if number == "1":
        KEY_TYPE = "RSA"
    elif number == "2":
        KEY_TYPE = "EC"
    elif number == "3":
        KEY_TYPE = "DSA"
    elif number == "4":
        KEY_TYPE = "ECDH"
    else:
        print("Error! Invalid input. Try again")
        define_key_type()

    print("Successfully set {} as key type".format(str(KEY_TYPE)))


def define_key_size():
    print("Which bit size should the key have?")
    print("Possible options are:\n(1) 2048 (default)\n(2) 4096")
    selection = input("Select one or press enter to use default: ")
    bit_size = 2048

    if selection == "2":
        bit_size = 4096

    return bit_size


def define_curve():
    print("To see a list of possible values for curves, run 'openssl ecparam -list_curves' or run the script with option --curves")
    curve = input("Enter the curve that should be used (default curve is 'prime256v1'): ")

    if curve == "":
        curve = "prime256v1"

    available_curves = get_available_curves()

    if curve in available_curves:
        print("Selected curve: {}".format(curve))
        return curve
    else:
        print("Given curve invalid! Try again")
        define_curve()


def list_curves():
    print("These elliptic curves are available for EC key generation: \n")
    execute_commands(["openssl ecparam -list_curves"])


def get_available_curves():
    command = "openssl ecparam -list_curves"
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0]
    output_string = str(output)[2: len(str(output)) - 1]
    lines = output_string.split("\\n")
    curves = []
    for line in lines:
        split_strings = line.split(":")
        curves.append(split_strings[0].replace(" ", ""))

    return curves


def create_parser():
    parser = argparse.ArgumentParser(prog="TLS KEYGEN",
                                     description="Input parameters for certificate and key generation")
    parser.add_argument("-a", action='store_true', help="Create a new certificate authority")
    parser.add_argument("-c", action='store_true', help="Create client certificate and key. CA key and cert must be set!")
    parser.add_argument("-s", action='store_true', help="Create server certificate and key. CA key and cert must be set!")
    parser.add_argument("--cakey", help="Define key location of an already existing CA")
    parser.add_argument("--cacert", help="Define certificate location of an already existing CA")
    parser.add_argument("--curves", action='store_true', help="Show a list of available elliptic curves")

    return parser


if __name__ == '__main__':
    init()
    print_banner()
    if not len(sys.argv[1:]):
        interactive_setup()
    else:
        arguments = create_parser().parse_args()
        if arguments.cakey is not None:
            path = os.path.abspath(arguments.cakey)
            if os.path.isfile(path) and (path.endswith(".pem") or path.endswith(".key")):
                CA_KEY_PATH = path

        if arguments.cacert is not None:
            path = os.path.abspath(arguments.cacert)
            if os.path.isfile(path) and (path.endswith(".pem") or path.endswith(".crt")):
                CA_CERT_PATH = path

        if arguments.curves:
            list_curves()

        if arguments.a:
            setup_ca()
            cleanup()
        if arguments.s:
            check_ca_paths()
            setup_sever()
            cleanup()
        if arguments.c:
            check_ca_paths()
            setup_client()
            cleanup()

