#pragma once

/// <summary>Encrypts and decrypts data using a LSFR feedback and a initialValue (Password). </summary>
/// <param name="data"> The data stream to be encrypted/decrypted</param>   
/// <param name="dataLength">The number of characters to encrypt/decrypt."</param>
/// <param name="initialValue">The password to encrypt/decrypt the data"</param>
/// <returns>The encrypted or decrypted data</returns>  
unsigned char* Crypt(unsigned char* data, int dataLength, unsigned int initialValue);

/// <summary>
/// Creates a key cypher stream using the following definition with current state S and feedback value F:
/// If Lowest bit of S is 0, S = S >> 1.
/// If Lowest bit of S is 1, S = (S >> 1) ^ F
/// </summary>
/// <param name="dataLength">The size of the data stream"</param>
/// <param name="initialValue">The initial state of the LSFR"</param>
/// <returns>The key cypher stream</returns>  
unsigned char* LSFR(int dataLength, unsigned int initialValue);

/// <summary>
/// XORs the data stream with the key stream.
/// </summary>
/// <param name="data"> The data stream to be encrypted/decrypted</param>   
/// <param name="keyStream"> The key stream</param>   
/// <param name="dataLength">The size of the data stream"</param>
/// <returns>The encrypted/decrypted data stream</returns>  
unsigned char* CryptWithXOR(unsigned char* data, unsigned char* keyStream, int dataLength);
