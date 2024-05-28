# Secure Communication Suite

## Project Description

This project aims to develop a Secure Communication Suite in Python, a comprehensive application that integrates various cryptographic techniques and security protocols. The suite features block ciphers for symmetric encryption, public key cryptosystems for asymmetric encryption, and hashing functions for data integrity. It also incorporates key management solutions for secure key distribution and storage, and authentication mechanisms to verify user identities. The application is designed to secure internet services, protecting data in transit and at rest.

## Features and Specifications

- **Block Cipher Module**: Implements AES or DES for symmetric encryption.
- **Public Key Cryptosystem Module**: Implements RSA or ECC for asymmetric encryption.
- **Hashing Module**: Implements SHA-256 or MD5 for data integrity checks.
- **Key Management Module**: Develops secure methods for key generation, distribution, and storage.
- **Authentication Module**: Implements password-based or certificate-based authentication mechanisms.
- **Internet Services Security Module**: Applies the cryptographic modules to secure data for internet services.

## User Stories

- **Message Encryption**: As a user, I want to encrypt my messages using a block cipher so that they can be securely transmitted.
- **Key Sharing**: As a user, I want to use public key cryptosystems to securely share keys with my communication partner.
- **Data Integrity Verification**: As a user, I want to verify the integrity of my received messages using hashing functions.
- **Secure Key Management**: As a user, I want to manage my cryptographic keys securely.
- **User Authentication**: As a user, I want to authenticate myself to the system to ensure secure access.
- **Securing Internet Services**: As a user, I want to secure my internet services using the provided cryptographic modules.

## File Structure

- **AESDES.py**: Contains the implementation of block cipher algorithms (AES/DES).
- **Client.py**: Handles client-side operations, including connecting to the server, sending/receiving messages, and encryption/decryption.
- **ECC.py**: Implements elliptic curve cryptography for asymmetric encryption.
- **Hashing.py**: Provides hashing functions for data integrity checks.
- **KeyManager.py**: Manages key generation, distribution, and storage securely.
- **RSA.py**: Implements RSA algorithm for asymmetric encryption.
- **Server.py**: Manages server-side operations, including handling client connections and broadcasting messages.
- **main.py**: The main application file that initializes the GUI and integrates all modules.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- PyQt5 for GUI
- pycryptodome library for cryptographic functions

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-communication-suite.git
   cd secure-communication-suite
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

1. **Run the Server**:
   ```bash
   python Server.py
   ```

2. **Run the Client**:
   ```bash
   python Client.py
   ```

3. **Run the Main Application**:
   ```bash
   python main.py
   ```

## Contributing

We welcome contributions to enhance the functionality and security of the Secure Communication Suite. Please fork the repository and create a pull request with your improvements.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For any questions or feedback, please reach out to [ziad.ashraf.ahmed.ahmed@gmail.com] or create an issue on GitHub.

