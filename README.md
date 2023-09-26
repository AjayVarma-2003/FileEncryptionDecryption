# FileEncryptionDecryption

This is CPP project to encrypt and decrypt the given file 

Following are some instructions about it :
1.We use OpenSSL's PBKDF2 function to derive a secure encryption key from a password and a random salt.
  So for this firstly install openssl in your device
2.The salt is generated randomly and saved in the output file, which is essential for decryption.

  What is Salt :
  
    In cryptography, a salt is a random value that is used as an additional input to a key derivation function (KDF) or a password hashing function. The purpose of a salt is to enhance      the security of cryptographic operations, particularly those involving passwords or other low-entropy inputs.

    Here's why salts are used and their importance:

    Randomness: Salts are generated as random values. They add an element of randomness to the process, which ensures that even if two users have the same password, their hashed values       will be different due to the unique salt.

    Protection Against Rainbow Tables: Attackers often use precomputed tables called "rainbow tables" to quickly look up the hash values of common passwords. Salting passwords makes it       infeasible to use rainbow tables effectively because each user's password has a unique salt.

    Prevents Identical Hashes: Without salts, identical passwords will always produce the same hash value. With salts, even if two users have the same password, their hashed values will     be different due to the unique salt, preventing attackers from recognizing identical passwords based on their hash values.

    Enhances Security: Salting passwords significantly enhances security and makes it more difficult for attackers to use techniques like dictionary attacks or brute force attacks to         guess passwords.

    Protection Against Collision Attacks: Salts help protect against collision attacks, where two different inputs produce the same hash value. With salts, the probability of two             different inputs colliding is extremely low.

    In the code example I provided earlier for key derivation using PBKDF2, the salt is generated randomly and used as input to the PBKDF2 function along with the user's password. This       ensures that the derived encryption key is unique for each user and is not predictable, even if two users have the same password.

    In summary, the concept of a salt is a crucial security measure in cryptography, especially when handling passwords or other low-entropy inputs, to prevent common attacks and             enhance the overall security of cryptographic operations.

  3.Encryption is performed using XOR with the derived encryption key, similar to the previous example.

  4.Please replace "input.txt", "encrypted.txt", and "MySecurePassword" with your desired file paths and password.

  5.compilation command for a C++ program that uses OpenSSL:
      g++ your_program.cpp -o your_program -I/usr/include/openssl -lssl -lcrypto

  Make sure to adjust the include and library paths to match your system's configuration.

  After making these adjustments, you should be able to compile your code without the "cannot open source file openssl/evp.h" error.
