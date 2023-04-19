# Nested Hashing PSI

[![REUSE status](https://api.reuse.software/badge/github.com/SAP/nested-hashing-psi)](https://api.reuse.software/info/github.com/SAP/nested-hashing-psi)

## Description

Private Set Intersection (PSI) is a famous secure two-party computation (2PC) problem where two parties (client and server) want to jointly compute the intersection of their inputs sets without revealing additional information about the input sets. Our implementation offers open-source research code to perform fast privacy-preserving set intersections for unbalanced set sizes (i.e., more server input items) with intersection output to the client.

## Requirements

This project has the following requirements:
- libscapi (with boost program options package): https://github.com/cryptobiu/libscapi
- OpenFHE: https://github.com/openfheorg/openfhe-development

Code repository for a Private Set Intersection (PSI) protocol in the asymmetric unbalanced case based on a new Cuckoo hashing structure and homomorphic encryption.

## Download and Installation

After installing the requirements and correctly setting the absolute path in ``PSIConfigs.h``, this project can be built using CMake.

We provide some unit tests for our protocol and the included libraries under /tests (which rely on third-party code from libscapi and OpenFHE tests).

After building with CMake, the protocol can be started with the Server and Client executables.
We have included several command line options which can be printed with the ``-h`` option. 

## How to obtain support
[Create an issue](https://github.com/SAP-samples/<repository-name>/issues) in this repository if you find a bug or have questions about the content.

## Contributing
If you wish to contribute code, offer fixes or improvements, please send a pull request. Due to legal reasons, contributors will be asked to accept a DCO when they create the first pull request to this project. This happens in an automated fashion during the submission process. SAP uses [the standard DCO text of the Linux Foundation](https://developercertificate.org/).

## License
Copyright 2022-2023 SAP SE or an SAP affiliate company and nested-hashing-psi contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/SAP/nested-hashing-psi).
