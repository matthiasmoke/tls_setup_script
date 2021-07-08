# Setup information for TLS with MQTT

## Script usage
This script can be used without any pre-configuration

    python tls_dispenser.py

When started without any parameters, the script is run in interactive-mode for the key and certificate generation.
For information on additional parameters, start it with `-h` like so:

    python tls_dispenser.py -h

Basic information for the certificate requests can be specified on runtime, but advanced information like extensions
need to be set within the respective configuration files. (`ca.conf`, `server.conf`, `client.conf`)

### Script output
The script creates several files, that are needed to create a TLS connection with a specific cipher suite:
- ca.crt: This is the certificate of the created certificate authority. It is needed by the broker to authenticate the CA signature on the microcontroller certificate and by the microcontroller to authenticate the CA signature on the broker certificate.
- ca.pem: This is the private key of the certificate authority. With this you can manually create new certificates for broker or microcontroller
- client.pem: This is the private key of the microcontroller, it must be added to the code of the microcontroller.
- client.crt: This is the certificate created for the microcontroller with the private key of the microcontroller and the private key of the certificate authority. To allow the microcontroller to provide this at a TLS connection, it must also be inserted in the microcontroller's code. 
- server.pem: This is the private key of the broker. It must be stored in the specified path provided by the configuration file of the broker.(Not the configuration files of the script)
- server.crt: This is the certificate created for the broker with the private key of the microcontroller and the private key of the certificate authority. This should also be stored in the path provided by the conifugation file of the broker.
  
## Setup of mosquitto

On the Raspberry PI OS lite (without desktop), the Mosquitto broker can be easily installed via apt.

    sudo apt install mosquitto

After successful installation, the configuration files can be found under 

    /etc/mosquitto/mosquitto.conf

Below is a snippet of the configuration, that contains the essential part for the connection via TLS 1.2.

    listener 8883
    # Only allow clients that authenticate themselves with an MQTT user
    allow_anonymous false
    # Password file that contains the MQTT users and their respective passwords
    password_file /home/pi/mqtt/p1.txt

    # Path to the CA certificate
    cafile /path/to/file/ca.crt
    # Path to the PEM encoded server certificate.
    certfile /path/to/file/server.crt
    # Path to the PEM encoded keyfile.
    keyfile /path/to/file/server.pem

    require_certificate true

    ciphers ECDHE-RSA-AES128-GCM-SHA256

The `listener` config options defines the port on which client can request a connection. Here, it's port 8883, as it is the standard port for MQTT in combination with TLS. But in genreal, any other free port can be set here.

The options `cafile`, `certfile` and `keyfile` define the paths to certificates and key required for the TLS connection.

With `require_certificate` set to true, the broker will ask the client to verify itself be sending its certificate, signed by the Certificate Authority given under `cafile`.

With the `ciphers` configuration option, one can define a list of ciphersuites the broker will support for an incoming connection. In the example configuration above, the broker only uses "ECDHE-RSA-AES128-GCM-SHA256" as ciphersuite and does not accept anything else.
Hence if the client does not support the cipher suite, TLS connection can not be established.

To check which ciphers can be used, the

    openssl ciphers

can be run. The command output is also the format in which the list of ciphers has to be given in the Mosquitto configuration.

### Create User File

Create text file with following content:

    testUser:1234

Then run command:

    mosquitto_passwd -U passwordfile

## Troubleshooting

### OpenSSL error: X
This error message occurs when both, server and CA, have the exact same certificate details in all possible attributes (Country, State, Locality, etc.). To prevent it, set different information in the certificate requests for server and CA. 
In the standard configuration files given, different information for the entities are set, so it is unlikely to run into this problem.