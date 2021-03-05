#include <string>
using namespace std;


/// <summary>
/// RUNS CHALLENGE 2 - Decrypts a KDB File and outputs the decrypted info
/// </summary>
int DecryptKDBMain();

/*
* ===================
* CLASS DECLARATIONS
* ===================
*/
/// <summary>Class for the Data node in the KDB file</summary>
class KDBData
{
public:
	char* encData;			//The encrypted data in the KDB File
	KDBData(__int16);		//Method to initialize encData size
};

/// <summary>Class for a KDB Block in the KDB file</summary>
class KDBBlock
{
public:
	__int16 size;			//Length of the Block's Data
	__int32 dataPtr;		//Pointer to the Block's Data in the KDB File

	KDBData* data;			//Pointer to the KDBData in system
};

/// <summary>Class for a KDB Block in the KDB file</summary>
class KDBEntry
{
public:
	char name[16];			//Null terminated entry name
	__int32 blockListPtr;	//Pointer to the Entry's Block List in the KDB File

	KDBBlock* blocks;		//Pointer to the Block List 
	int numBlocks;			//Number of blocks in the block list

	unsigned char* decData;	//The decrypted data of all blocks concatenated
	int dataSize;			//The size in bytes of the decrypted data
};

/// <summary>Class for a KDB object. Use decryptKDB to populate object info</summary>
class KDB
{
public:
	unsigned char magic[6];		//"CT2018"
	__int32 entryListPtrPos;	//Pointer to the entry list in the KDB File

	KDBEntry* entries;			//Pointer to the entry list 
	int numEntries;				//Number of entries in the entry list
};

bool openInputFile(fstream& inputFile, string prompt, string &pathName);

KDB& DecryptKDB(fstream& kdbFile,bool &error, bool printEntries = true);