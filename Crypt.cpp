#include <iostream>
#include "Crypt.h"
using namespace std;

//CONSTANTS
const unsigned int FEEDBACK_VAL = 0x87654321;      //The feedback value for this LSFR that is XOR'd with the current LSFR value. 


/// <summary>Encrypts and decrypts data using a LSFR feedback and a initialValue (Password). </summary>
/// <param name="data"> The data stream to be encrypted/decrypted</param>   
/// <param name="dataLength">The number of characters to encrypt/decrypt."</param>
/// <param name="initialValue">The password to encrypt/decrypt the data"</param>
/// <returns>The encrypted or decrypted data</returns>  
unsigned char* Crypt(unsigned char* data, int dataLength, unsigned int initialValue)
{
    //Sanity Checks
    if (data == nullptr || dataLength <= 0) return data;

    unsigned char* keyStream = LSFR(dataLength,initialValue);
    return CryptWithXOR(data, keyStream, dataLength);
}

/// <summary>
/// Creates a key cypher stream using the following definition with current state S and feedback value F:
/// If Lowest bit of S is 0, S = S >> 1.
/// If Lowest bit of S is 1, S = (S >> 1) ^ F
/// </summary>
/// <param name="dataLength">The size of the data stream"</param>
/// <param name="initialValue">The initial state of the LSFR"</param>
/// <returns>The key cypher stream</returns>  
unsigned char* LSFR(int dataLength, unsigned int initialValue)
{
    unsigned char* keyStream = new unsigned char[dataLength];
    unsigned int currentValue = initialValue;

    //Get a keyStream that is dataLength big where each key is the last byte of the value after the 8th step. 
    for (int keyCount = 0; keyCount < dataLength; keyCount++) {
        for (int stepCount = 0; stepCount < 8; stepCount++) {
            // Even Case: S = S >> 1
            if (currentValue % 2 == 0) currentValue = currentValue >> 1;
            // Odd Case: S = (S >> 1) ^ F
            else currentValue = (currentValue >> 1) ^ FEEDBACK_VAL;
        }
        keyStream[keyCount] = (char)(currentValue & 0xFF);  //Mask the current value to get the last byte. 
    }

    return keyStream;
}

/// <summary>
/// XORs the data stream with the key stream.
/// </summary>
/// <param name="data"> The data stream to be encrypted/decrypted</param>   
/// <param name="keyStream"> The key stream</param>   
/// <param name="dataLength">The size of the data stream"</param>
/// <returns>The encrypted/decrypted data stream</returns>  
unsigned char* CryptWithXOR(unsigned char* data, unsigned char* keyStream, int dataLength) 
{
    unsigned char* outputStr = new unsigned char[dataLength];

    //XOR the strings together
    for (int pos = 0; pos < dataLength; pos++) {
        outputStr[pos] = data[pos] ^ keyStream[pos];
    }
    return outputStr;
}
