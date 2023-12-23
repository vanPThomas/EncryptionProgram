#include <iostream>
#include <fstream>
#include <string>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

std::string generateEncryptionKey()
{
    const int keySize = 16; // AES-128 key size in bytes
    unsigned char key[keySize];

    if (RAND_bytes(key, keySize) != 1)
    {
        std::cerr << "Error generating random key." << std::endl;
        exit(EXIT_FAILURE);
    }

    return std::string(reinterpret_cast<char *>(key), keySize);
}

std::string encryptData(const std::string &data, const std::string &key)
{
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.c_str()), nullptr))
    {
        std::cerr << "Error initializing encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    int len;
    int ciphertextLen;
    std::string ciphertext(data.size() + AES_BLOCK_SIZE, '\0');

    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()))
    {
        std::cerr << "Error updating encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    ciphertextLen = len;

    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&ciphertext[len]), &len))
    {
        std::cerr << "Error finalizing encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext.substr(0, ciphertextLen);
}

int main()
{
    // Get password from the user
    std::cout << "Enter password: ";
    std::string password;
    std::getline(std::cin, password);

    // Generate encryption key
    std::string encryptionKey = generateEncryptionKey();

    std::cout << encryptionKey << std::endl;

    // Encrypt the key using the password
    std::string encryptedKey = encryptData(encryptionKey, password);

    // Write the encrypted key to a file
    std::ofstream outFile("encrypted_key.txt");
    if (!outFile)
    {
        std::cerr << "Error opening file for writing." << std::endl;
        return EXIT_FAILURE;
    }

    outFile << encryptedKey;
    outFile.close();

    std::cout << "Encryption key successfully encrypted and written to 'encrypted_key.txt'." << std::endl;

    return EXIT_SUCCESS;
}
