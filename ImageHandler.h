#include <string>

using namespace std;

/// <summary>
/// RUNS CHALLENGE 3 - Extracts/Repairs/Saves/Outputs the magic jpegs in a file
/// </summary>
int ImageHandlerMain();

/// <summary>
/// The core logic for challenge 3. This processes an input file to extract/repair/save the magic jpeg files.
/// </summary>
/// <param name=imagePath>The filepath of the image</param>
/// <param name=kdbPath>The filepath of the KDB file</param>
void ImageHandler(string imagePath = "", string kdbPath = "");
