#ifndef EZ_FILE_H_
#define EZ_FILE_H_

#include <ntddk.h>

// Write files in a coverage
NTSTATUS EzWriteFile(IN const char* FileName, IN char* Data, IN SIZE_T Size);

// Read the file, if the file does not exist, you can't read anything
// The data read is stored in a non -split memory, and the person needs to be released
NTSTATUS EzReadFile(IN const char* FileName, OUT char** Data, OUT SIZE_T* DataSize);

// Delete files in conventional ways
NTSTATUS EzDeleteFile(IN const char* FileName);
#endif
