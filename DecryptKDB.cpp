#include <string>
#include <fstream>
#include <iostream>
#include "DecryptKDB.h"
#include "Crypt.h"
using namespace std;
	
/*
 * ===================
 * CONSTANTS
 * ==================
*/
const int MAX_ENTRIES = 127;					//Max number of entries in an entrylist
const int MAX_BLOCKS = 255;						//Max number of blocks in a blocklist
const int LSFR_INIT_VALUE = 0x4F574154;			//= 0x4F574154 , LSFR Initial Value to encrypt/decrypt KDB Files
const char* ENDSTRING = "\xFF\xFF\xFF\xFF";		//String found at the end of a block list or entry list in the KDB File.	

/// <summary>
/// RUNS CHALLENGE 2 - Decrypts a KDB File and outputs the decrypted info
/// </summary>
int DecryptKDBMain() {
	string path = "";
	fstream kdbFile;
	bool error = false;

	//SAMPLE PATH:
	//path="C:/Users/colin/Downloads/SW_2018/SW_2018/store.kdb";
	if (!openInputFile(kdbFile, "Enter KDB FilePath:", path)) return 1;
	DecryptKDB(kdbFile,error,true);
	kdbFile.close();
	return 1;
}


/*
 * =================== 
 * CONSTRUCTORS
 * ==================
 */
KDBData::KDBData(__int16 size)
{
	encData = new char[size];
}

/*
* ===================
* HELPER FUNCTIONS
* ===================
*/

/// <summary>
/// Reads the head data from the kdb file and saves the corresponding data into the KDB object
/// </summary>
/// <param name="kdb">The kdb object to save head info into</param>
/// <param name="kdbFile">The KDB file to be processed</param>
/// <returns>true on success, false on failed</returns>  
bool getKDBHead(KDB &kdb, fstream &kdbFile) 
{
	//Read the file for the magic string and the entry list pointer.
	kdbFile.read((char*)&kdb.magic, sizeof(kdb.magic));
	kdbFile.read((char*)&kdb.entryListPtrPos, sizeof(kdb.entryListPtrPos));
	if (strncmp((const char*)kdb.magic, "CT2018", 6) != 0)
	{
		cout << "Not a valid KDB File";
		return 0;
	}
	return 1;
}

/// <summary>
/// Reads the entry list and entry data from the kdb file and saves the corresponding data into the KDB object
/// </summary>
/// <param name="kdb">The kdb object to save entry list info into</param>
/// <param name="kdbFile">The KDB file to be processed</param>
/// <returns>true on success, false on failed</returns>  
bool getKDBEntryList(KDB &kdb, fstream &kdbFile) 
{
	char tempBuffer4[4];		//4 byte buffer
	char tempBuffer16[16]; 		//16 byte buffer
	int numEntries = 0;			//Count of entries

	KDBEntry* entryList = new KDBEntry[MAX_ENTRIES];

	kdbFile.clear();					//Clear is used in case we went beyond EOF earlier (shouldn't occur). 
	kdbFile.seekg(kdb.entryListPtrPos);	//Go to entry list position in file.

	//Read and verify the first 4 bytes then save the whole 20 bytes into each entry.
	kdbFile.read(tempBuffer4, 4);
	while (numEntries < MAX_ENTRIES && strncmp(tempBuffer4, ENDSTRING, 4) != 0)
	{
		//Note tempBufferSmall has the original 4 bytes, so we need to read 12 more bytes.
		kdbFile.read(tempBuffer16, 12);
		memcpy((char*)&entryList[numEntries].name, tempBuffer4, 4);
		memcpy((char*)&entryList[numEntries].name + 4, tempBuffer16, 12);
		kdbFile.read((char*)&entryList[numEntries].blockListPtr, 4);

		//Read off the next 4 bytes for next verification. 
		kdbFile.read(tempBuffer4, 4);
		numEntries++;
	}
	kdb.entries = entryList;
	kdb.numEntries = numEntries;
	return 1;
}

/// <summary>
/// Reads the block list and data from the kdb file and saves the corresponding data into the KDB object
/// </summary>
/// <param name="kdb">The kdb object to save entry list info into</param>
/// <param name="kdbFile">The KDB file to be processed</param>
/// <returns>true on success, false on failed</returns>  
bool getKDBCore(KDB &kdb, fstream &kdbFile)
{
	int entryIndex;			//Index in the entry list
	int blockIndex;			//Index in the block list
	int numBlocks;			//Total number of blocks in block list
	char tempBuffer8[8];	//8 byte buffer

	KDBBlock* blockList;
	string tempEncString;	//Encrypted data string
	int totalDataSize;		//Encrypted data string size

	//Iterate over every entry to process a corresponding block list. 
	//After processing the block list, process the data for each block in the block list.
	for (entryIndex = 0; entryIndex < kdb.numEntries; entryIndex++)
	{
		//Initialize Block List elements
		numBlocks = 0;
		blockList = new KDBBlock[MAX_BLOCKS];
		//Initialize Encrypted Data elements
		totalDataSize = 0;
		tempEncString = "";

		//Go to Block List position in file.
		kdbFile.clear();
		kdbFile.seekg(kdb.entries[entryIndex].blockListPtr);

		//Read a single block (6 bytes) into a buffer to verify before saving.
		kdbFile.read(tempBuffer8, 6);
		while (numBlocks < MAX_BLOCKS && strncmp(tempBuffer8, ENDSTRING, 4) != 0)
		{
			//Save the 6 bytes into the block
			memcpy(&blockList[numBlocks].size, tempBuffer8, 2);
			memcpy(&blockList[numBlocks].dataPtr, tempBuffer8 + 2, 4);

			//Create a data node in the block of the corresponding size
			blockList[numBlocks].data = new KDBData(blockList[numBlocks].size);

			//Read off the next 6 bytes for verification
			kdbFile.read(tempBuffer8, 6);
			numBlocks++;
		}

		//Populate the data node in each block by reading the data node in the KDB file and keeping track of the output.
		for (blockIndex = 0; blockIndex < numBlocks; blockIndex++)
		{
			//Go to the data position in the file and read it into encData
			kdbFile.clear();
			kdbFile.seekg(blockList[blockIndex].dataPtr);
			kdbFile.read(blockList[blockIndex].data->encData, blockList[blockIndex].size);

			//Concatenate the encrypted data string to the full data string to be decrypted. This could probably be updated to be more efficient.
			tempEncString.append(blockList[blockIndex].data->encData, blockList[blockIndex].size);

			totalDataSize += blockList[blockIndex].size;
		}

		//Finalize the entries data. Note that Crypt outputs a unsigned char* with size totalDataSize. 
		//This means that the decData may not be null-terminated. 
		kdb.entries[entryIndex].numBlocks = numBlocks;
		kdb.entries[entryIndex].blocks = blockList;
		kdb.entries[entryIndex].decData = Crypt((unsigned char*)(tempEncString.c_str()), totalDataSize, LSFR_INIT_VALUE);
		kdb.entries[entryIndex].dataSize = totalDataSize;
	}
	return 1;
}

/// <summary>
/// Prompts the user if needed and opens an input file in binary mode. 
/// </summary>
/// <param name="inputFile">The file to be opened</param>
/// <param name="prompt">The file prompt</param>
/// <param name="pathName">The file pathName, "" by default</param>
/// <returns>true on success, false on failed</returns>  
bool openInputFile(fstream& inputFile, string prompt, string &pathName)
{
	if (pathName == "") {
		cout << prompt;
		cin >> pathName;
	}

	inputFile.open(pathName, ios::in | ios::binary);
	if (!inputFile.is_open())
	{
		cout << "File Does Not Exist\n";
		return 0;
	}
	return 1;
}

/*
* ===================
* MAIN FUNCTIONS
* ===================
*/

/// <summary>
/// Decrypts a .kdb file and outputs the decrypted entries
/// </summary>
/// <param name="kdbFile">The KDB file to be processed</param>
/// <param name="error">Outputs 1 if an error is found</param>
/// <param name=printEntries>If true then print out the decrypted info</param>
/// <returns>The processed KDB object</returns>
KDB& DecryptKDB(fstream &kdbFile, bool& error,bool printEntries)
{
	KDB newKDB;
	error = false;

	//KDB HEAD
	if (!getKDBHead(newKDB, kdbFile))
	{
		error = true;
		return newKDB;
	}

	//KDB ENTRY LIST
	if (!getKDBEntryList(newKDB, kdbFile)) 
	{
		error = true;
		return newKDB;
	};

	//KDB BLOCK LIST and DATA
	if (!getKDBCore(newKDB, kdbFile)) 
	{
		error = true;
		return newKDB;
	}

	//Output to standard output
	if (printEntries)
	{
		for (int entryIndex = 0; entryIndex < (newKDB).numEntries; entryIndex++)
		{
			cout << (newKDB).entries[entryIndex].name << " - ";
			for (int index = 0; index < (newKDB).entries[entryIndex].dataSize; index++)
			{
				cout << (newKDB).entries[entryIndex].decData[index];
			}
			cout << "\n";
		}
	}

	return newKDB;
}

