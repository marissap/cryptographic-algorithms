//
//  main.cpp
//  CryptoProject
//
//  Created by Marissa on 2020-11-27.
//

#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/ecp.h>
#include <cryptopp/modes.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <fstream>
#include <chrono>
using namespace std;

void encryptionAES(string plaintext) {
    // Generate an AES 128 key
    auto startKey = std::chrono::high_resolution_clock::now();
    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    auto endKey = std::chrono::high_resolution_clock::now();
    
    // Record the key generation time for AES 128
    std::chrono::duration<double, std::milli> durationKey = endKey - startKey;
    cout << "AES key generation duration: " << durationKey.count() << " ms" <<  endl;
    
    // Encrypt the plaintext using the AES 128 key
    auto startEncryption = std::chrono::high_resolution_clock::now();
    string ciphertext;
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() );
    stfEncryptor.MessageEnd();
    auto endEncryption = std::chrono::high_resolution_clock::now();
    
    // Record the encryption time for AES 128
    std::chrono::duration<double, std::milli> durationEncryption = endEncryption - startEncryption;
    cout << "AES encryption duration: " << durationEncryption.count() << " ms" << endl;
}

void encryptionECP(string plaintext) {
    // Generate an ECP 256 key
    auto startKey = std::chrono::high_resolution_clock::now();
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor d0(prng, CryptoPP::ASN1::secp256k1());
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor e0(d0);
    auto endKey = std::chrono::high_resolution_clock::now();
    
    // Record the key generation time for AES 128
    std::chrono::duration<double, std::milli> durationKey = endKey - startKey;
    cout << "ECP key generation duration: " << durationKey.count() << " ms" <<  endl;
    
    // Encrypt the plaintext using the ECP 256 key
    auto startEncryption = std::chrono::high_resolution_clock::now();
    string em0;
    CryptoPP::StringSource ss1 (plaintext, true, new CryptoPP::PK_EncryptorFilter(prng, e0, new CryptoPP::StringSink(em0) ) );
    string dm0;
    CryptoPP::StringSource ss2 (em0, true, new CryptoPP::PK_DecryptorFilter(prng, d0, new CryptoPP::StringSink(dm0) ) );
    auto endEncryption = std::chrono::high_resolution_clock::now();
    
    // Record the encryption time for AES 128
    std::chrono::duration<double, std::milli> durationEncryption = endEncryption - startEncryption;
    cout << "ECP encryption duration: " << durationEncryption.count() << " ms" << endl;
}

string readFile(string fileName) {
    ifstream file;
    file.open(fileName);
    string line;
    string plaintext;
    if (file.is_open()) {
        while ( getline (file,line) ) {
            plaintext = plaintext + line;
        }
          file.close();
    }
    return plaintext;
}

int main(int argc, const char * argv[]) {
    
    cout << "Beginning encryption process for file 1" << endl;
    string plaintext1 = readFile("file1MB.txt");
    encryptionAES(plaintext1);
    encryptionECP(plaintext1);
    
    cout << "Beginning encryption process for file 2" << endl;
    string plaintext2 = readFile("file2MB.txt");
    encryptionAES(plaintext2);
    encryptionECP(plaintext2);
    
    cout << "Beginning encryption process for file 3" << endl;
    string plaintext3 = readFile("file3MB.txt");
    encryptionAES(plaintext3);
    encryptionECP(plaintext3);
    
    cout << "Beginning encryption process for file 4" << endl;
    string plaintext4 = readFile("file4MB.txt");
    encryptionAES(plaintext4);
    encryptionECP(plaintext4);
    
    cout << "Beginning encryption process for file 5" << endl;
    string plaintext5 = readFile("file5MB.txt");
    encryptionAES(plaintext5);
    encryptionECP(plaintext5);
    
    return 0;
}
