//Problem Statement : File Encryption/Decryption: 
//Develop a tool that can encrypt and decrypt text files using a simple encryption algorithm like Caesar cipher or XOR encryption.

//conclusion : We have to build the tool that will encrypt the file using simple encryption method
//             It will take password, salt, saltlength, keylength, iterations, hashFunction.
//             And gives the Output as key:A buffer to store the derived key

//Algorithm 
/*
    START

        Initialize an internal buffer U of the same size as the hash function's output (in this case, 256 bits or 32 bytes).

        Calculate the block count (blockCount) by dividing keyLength by the hash function's output size. If there's a remainder, increment blockCount by 1.

        For each block i from 1 to blockCount:
        Initialize an innerKey by concatenating U with the 4-byte representation of i in big-endian byte order.
        Initialize an outerKey as a copy of innerKey.
        For each iteration from 1 to iterations:


        Calculate innerHash by applying the HMAC function with innerKey as the key and password as the message.
        Calculate outerHash by applying the HMAC function with outerKey as the key and innerHash as the message.
        XOR U with outerHash.
        Concatenate U with the derived key (key).

        If the length of the derived key (key) exceeds keyLength, truncate it to keyLength bytes.

        The derived key is now stored in the key buffer and can be used for encryption, decryption, or any other cryptographic operations.

    STOP
*/

//Programming Language used : C++

//Program :

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
using namespace std;

//////////////////////////////////////////////////////////////////////////////////////
//
// Function Name : deriveKeyFromPassword
// Description :   Function to derive an encryption key from a password using PBKDF2
// Input :         character , unsigned character , integer , unsigned character
// Output :        password , salt , saltlength , keylength , key
// Author :        Ajay Yogesh Varma
// Date :          26-09-2023
//
//////////////////////////////////////////////////////////////////////////////////////

void deriveKeyFromPassword(const char *password, const unsigned char *salt, int saltLength, unsigned char *key, int keyLength)
{
    const int iterations = 10000; // Number of PBKDF2 iterations (adjust as needed)
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, saltLength, iterations, EVP_sha256(), keyLength, key);
}
 
//////////////////////////////////////////////////////////////////////////////////////
//
// Function Name : encryptFile
// Description :   Function to encrypt a file using XOR
// Input :         character , character , character
// Output :        Salt , Encrypted Data , File Format
// Author :        Ajay Yogesh Varma
// Date :          26-09-2023
//
//////////////////////////////////////////////////////////////////////////////////////

void encryptFile(const char *inputFileName, const char *outputFileName, const char *password)
{
    ifstream inputFile(inputFileName, ios::binary);
    ofstream outputFile(outputFileName, ios::binary);

    if (!inputFile || !outputFile)
    {
        cerr << "Error opening files." << endl;
        return;
    }

    // Generate a random salt for key derivation
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    // Derive the encryption key from the password
    unsigned char encryptionKey[32];
    deriveKeyFromPassword(password, salt, sizeof(salt), encryptionKey, sizeof(encryptionKey));

    // Write the salt to the output file (for later use during decryption)
    outputFile.write(reinterpret_cast<char *>(salt), sizeof(salt));

    char ch;
    int keyIndex = 0;
    while (inputFile.get(ch))
    {
        // XOR each character with the key character
        char encryptedChar = ch ^ encryptionKey[keyIndex];
        outputFile.put(encryptedChar);

        // Move to the next key character or wrap around
        keyIndex = (keyIndex + 1) % sizeof(encryptionKey);
    }

    inputFile.close();
    outputFile.close();
    cout << "Encryption complete." << endl;
}

//////////////////////////////////////////////////////////////////////////////////////
//
// It is entry point function where program will start to execute encryption and 
// decryption of the file provided.
//
//////////////////////////////////////////////////////////////////////////////////////

int main()
{
    const char *inputFileName = "input.txt";         // Replace with your input file
    const char *encryptedFileName = "encrypted.txt"; // Replace with your encrypted file
    const char *password = "MySecurePassword";       // Replace with your password

    // Encrypt the input file
    encryptFile(inputFileName, encryptedFileName, password);

    return 0;
}
