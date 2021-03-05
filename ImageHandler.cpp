#include <string>
#include <fstream>
#include <iostream>
#include <list>
#include <windows.h>
#include <openssl/md5.h>
#include "DecryptKDB.h"
#include "ImageHandler.h"

const int PATH_LENGTH = 260;					//File path length
const int BUFFER_SIZE = 2048;					//Buffer size in bytes
const char* END_STRING = "\xFF\xD9";			//0xFFD9 - The end bytes of a jpeg image
const char* JPG_STRING = "\xFF\xD8\xFF";		//0xFFD8FF - The starting bytes of a jpeg image
const int END_STRING_SIZE = 2;					//The length of the end string of a jpeg image

/// <summary>
/// RUNS CHALLENGE 3 - Extracts/Repairs/Saves/Outputs the magic jpegs in a file
/// </summary>
int ImageHandlerMain()
{
	string kdbPath = "";
	string imagePath = "";
	
	//SAMPLE PATHS:
	//kdbPath = "C:/Users/colin/Downloads/SW_2018/SW_2018/magic.kdb";
	//imagePath = "C:/Users/colin/Downloads/SW_2018/SW_2018/input.bin";
	
	ImageHandler(imagePath, kdbPath);
	return 1;
}

/// <summary>
/// Searches the Image file for all Magic jpegs. Outputs the offsets into offsetList and endOffsetList
/// </summary>
/// <param name="imageFile">The image file to be searched</param>
/// <param name="offsetList">An outputted list of the starting position of the magic jpegs in the file</param>
/// <param name=endOffsetList>A outputted list of the ending position of the magic jpegs in the file</param>
/// <param name=magic>The magic string to search for</param>
/// <param name=magicSize>The number of characters in the magic string</param>
void searchForMagicJPEGS(fstream &imageFile, list<int>& offsetList, list<int>& endOffsetList, unsigned char* magic, int magicSize)
{
	unsigned char buffer[BUFFER_SIZE];

	bool match;
	bool findEnd = false;

	int patternIndex;
	int curPatternSize;
	int maxPatternSize = max(magicSize, END_STRING_SIZE);
	int filePos = 0;

	if (findEnd) curPatternSize = END_STRING_SIZE;
	else curPatternSize = magicSize;

	imageFile.seekg(filePos);
	while (!imageFile.eof())
	{
		imageFile.seekg(filePos);
		imageFile.read((char*)buffer, BUFFER_SIZE);

		//A search across the buffer for the magic string OR the JPG end string. 
		//After the magic string is found we search for the JPG end string and keep alternating.
		//Each time one of the strings is found we insert the position into the offsetList or the endOffsetList.
		for (int bufferIndex = 0; bufferIndex < BUFFER_SIZE - maxPatternSize; bufferIndex++)
		{
			match = true;
			patternIndex = 0;
			//Check if the next bytes matches magic. Quit early if the string does not match the magic or the end_string.
			while ((patternIndex < curPatternSize) && match == true)
			{
				if (findEnd && buffer[bufferIndex + patternIndex] != (unsigned char)END_STRING[patternIndex]) match = false;
				else if (!findEnd && buffer[bufferIndex + patternIndex] != magic[patternIndex]) match = false;
				patternIndex++;
			}

			//If the bytes are found, we swap the search and push the position onto the end of the list. 
			if (match == true)
			{
				if (findEnd)
				{
					findEnd = false;
					curPatternSize = magicSize;
					endOffsetList.push_back(filePos + bufferIndex + END_STRING_SIZE); //Add an offset to account for file position to buffer position.
				}
				else
				{
					findEnd = true;
					curPatternSize = END_STRING_SIZE;
					offsetList.push_back(filePos + bufferIndex);					//Add an offset to account for file position to buffer position.
				}
			}
		}

		filePos += BUFFER_SIZE - maxPatternSize;
	}
}

/// <summary>
/// Gets the Magic bytes and size in the KDB File. 
/// </summary>
/// <param name=kdbFile>The KDB file to be processed</param>
/// <param name=magicSize>The number of characters in the magic string</param>
/// <param name=error>outputted as true if an error was encountered</param>
/// <return>The magic bytes in the KDB file</param>
unsigned char *getMagicBytesFromKDB(fstream& kdbFile, int &magicSize, bool &error) 
{
	unsigned char* magicBytes = nullptr;
	int entryCount = 0;
	KDB kdb = DecryptKDB(kdbFile, error, false);

	//Here we assume that all MAGIC entries have the same data. 
	while (entryCount < kdb.numEntries && magicBytes==nullptr)
	{
		if (strncmp(kdb.entries[entryCount].name, "MAGIC", 5) == 0)
		{
			magicSize = kdb.entries[entryCount].dataSize;
			magicBytes = new unsigned char[magicSize];
			memcpy(magicBytes, (kdb.entries[entryCount].decData), magicSize);
		}
		entryCount++;
	}
	return magicBytes;
}

/// <summary>
/// Prints out the repaired image details
/// </summary>
/// <param name=offset>The offset of the image position in the input file</param>
/// <param name=size>The image size in bytes</param>
/// <param name=md5Hash>The md5 hash of the image</param>
/// <param name=path>The filepath of the image</param>
void printImageOutput(int offset, int size, unsigned char * md5Hash, string path) 
{
	cout << "Offset - " << offset << "\n";
	cout << "Size - " << size << "\n";
	cout << "Hash - ";
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		printf("%X", md5Hash[i]);
	}
	cout << "\n";
	cout << "Path - " << path << "\n";
	cout << "\n\n";
}

/// <summary>
/// The core logic for challenge 3. This processes an input file to extract/repair/save the magic jpeg files.
/// </summary>
/// <param name=imagePath>The filepath of the image</param>
/// <param name=kdbPath>The filepath of the KDB file</param>
void ImageHandler(string imagePath, string kdbPath)
{
	fstream imageFile, kdbFile, outImageFile;
	
	char drive[PATH_LENGTH], dir[PATH_LENGTH], filename[PATH_LENGTH],ext[PATH_LENGTH];
	unsigned char md5Hash[MD5_DIGEST_LENGTH], buffer[BUFFER_SIZE];
	unsigned char* magicBytes = nullptr;

	int magicSize, remainingBytes, jpegSize;
	bool error = false;

	list<int> offsetList, endOffsetList;			//These contain the start/end positions of the jpeg images in the image file.
	list<int>::iterator startOffset, endOffset;			

	string outputPath, newParentDir;
	MD5_CTX mdContext;

	//File being opened, make sure to close the files as well.
	if (!openInputFile(kdbFile, "Enter KDB File Path:", kdbPath)) return;
	if (!openInputFile(imageFile, "Enter Image File Path:", imagePath)) { kdbFile.close(); return; }

	cout << "\n\n";
	_splitpath_s(imagePath.c_str(), drive, dir, filename, ext);		//These are stripped out since we'll be creating a new dir + new files. 

	//Load Magic Bytes from KDB File
	magicBytes = getMagicBytesFromKDB(kdbFile, magicSize, error);
	kdbFile.close();
	if (error) {
		cout << "Decrypting KDB File Failed\n";
		imageFile.close(); 
		return;
	}
	if (magicBytes == nullptr) {
		cout << "No Magic JPEG found";
		imageFile.close();
		return;
	}

	//Get an offset list of the magic'd jpeg files in the image file
	searchForMagicJPEGS(imageFile, offsetList, endOffsetList, magicBytes, magicSize);

	startOffset = offsetList.begin();
	endOffset = endOffsetList.begin();
	
	newParentDir = (string)drive+(string)dir + (string)filename + "_Repaired/";
	CreateDirectory(newParentDir.c_str(), NULL); //Automatically returns if path exists

	cout << "----------------------- REPAIRED JPEGS -----------------------\n";
	//Loop through every offset (JPEG) image and process the data.
	//Processing the data includes
	//1. Repairing the JPEG to include the correct magic bytes
	//2. Saving the JPEG into a separate file
	//3. Printing out the file details (offset, size, MD5 hash, path).
	for (int offsetIndex = 0; offsetIndex < offsetList.size(); offsetIndex++)
	{
		//Create the output file to write to - <parentDir>/<filename>_Repaired/<offset>.jpeg
		outputPath = newParentDir + to_string(*startOffset) + ".jpeg";
		outImageFile.open(outputPath, ios::out | ios::binary | ios::trunc);
		
		MD5_Init(&mdContext);
		jpegSize = *endOffset-*startOffset;
		imageFile.clear();
		imageFile.seekg(*startOffset + magicSize);

		//Write to the file the magic byte. Hash the magic bytes
		outImageFile.write(JPG_STRING, 3);
		MD5_Update(&mdContext, JPG_STRING, 3);

		//Fill the buffer as many times as possible from the magic byte position. Then write and hash the data.
		for (int index = 0; index < (jpegSize - magicSize) / BUFFER_SIZE; index++)
		{
			imageFile.read((char*) buffer, BUFFER_SIZE);
			outImageFile.write((char*) buffer, BUFFER_SIZE);
			MD5_Update(&mdContext, buffer, BUFFER_SIZE);
		}

		//The buffer wasn't able to be fully filled in the last loop, so now we read/write/hash the remaining data. 
		remainingBytes = (jpegSize - magicSize) % BUFFER_SIZE;
		if (remainingBytes > 0) 
		{
			imageFile.read((char*)buffer, remainingBytes);
			outImageFile.write((char*)buffer, remainingBytes);
			MD5_Update(&mdContext, buffer, remainingBytes);
		}

		outImageFile.close();
		MD5_Final(md5Hash, &mdContext);

		printImageOutput(*startOffset, jpegSize, md5Hash, outputPath);

		startOffset++;
		endOffset++;
	}

	delete [] magicBytes;
	imageFile.close();
}