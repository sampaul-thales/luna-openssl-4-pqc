
# Luna Crypto Provider (lunaprov)

This project offers a plugin to Open SSL (3.2) for the purpose of generating and using cryptographic keys on a [Luna General Purpose HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/general-purpose-hsms), and more specifically [Luna Network HSMs](https://cpl.thalesgroup.com/encryption/hardware-security-modules/network-hsms). 

## Introduction

lunaprov is based on the [PKCS#11 specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html), with some [Luna specific extensions](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/pkcs11/pkcs11_standard.htm).

It has been tested with the Luna Network HSM.

lunaprov allows to:
-	Create keypair (RSA, DSA, EC, PQC, ED25519/448, X25519/448).
-	Sign certificate or other data.
-   Establish TLS connection (KEM and certificate authentication).

These operations require to create partitions, register clients, initialize user roles, etc. These tasks can be performed using:
- The [Luna Universal Client](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/Utilities/Preface.htm)
  - The [Luna Shell (Lush)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunash/Preface.htm)
  - The [Luna client management tool (LunaCM)](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/lunacm/Preface.htm).

## Minimum System Requirements

- Operating System:
  - Linux RHEL 8.
  - Linux Ubuntu 20.
  - Windows Server 2016-2022.
- Thales software:
  - Client 10.7.1.
  - Appliance 7.7.1.
  - Firmware 7.7.1.
  - NOTE: if using Functional Modules then PQC FM 3.1.
  
## Minimum Build Requirements

- Development tools:
  - Linux:
    - gcc 8.3.1.
    - perl 5.16.3.
    - cmake3 3.17.5.
    - common UNIX commands.
  - Windows:
    - cl 19.00.24215.1 (Visual Studio 2015-2019).
    - perl 5.32.1 (ActiveState or Strawberry).
    - cmake 3.27.9 (Kitware).
    - common UNIX commands (MinGW or Cygwin).

## Run

For more details see the folder 'docs'.

## Test

The folder 'tests' contains scripts that exercise the HSM via openssl command line utility.

## Contributing

If you are interested in contributing to this project, please read the [Contributing guide](CONTRIBUTING.md).

## License

This software is provided under a [permissive license](LICENSE).
