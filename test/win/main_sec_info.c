// https://learn.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--
#include <stdio.h>
// #include <accctrl.h>
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")

int main(void)
{
DWORD dwRtnCode = 0;
PSID pSidOwner = NULL;
BOOL bRtnBool = TRUE;
LPWSTR AcctName = NULL;
LPWSTR DomainName = NULL;
DWORD dwAcctName = 1, dwDomainName = 1;
SID_NAME_USE eUse = SidTypeUnknown;
HANDLE hFile;
PSECURITY_DESCRIPTOR pSD = NULL;


// Get the handle of the file object.
hFile = CreateFile(
                  TEXT("myfile.txt"),
                  GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  NULL,
                  CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL,
                  NULL);

// Check GetLastError for CreateFile error code.
if (hFile == INVALID_HANDLE_VALUE) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();
          wprintf(L"CreateFile error = %lu\n", dwErrorCode);
          return -1;
}



// Get the owner SID of the file.
dwRtnCode = GetSecurityInfo(
                  hFile,
                  SE_FILE_OBJECT,
                  OWNER_SECURITY_INFORMATION,
                  &pSidOwner,
                  NULL,
                  NULL,
                  NULL,
                  &pSD);

// Check GetLastError for GetSecurityInfo error condition.
if (dwRtnCode != ERROR_SUCCESS) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();
          wprintf(L"GetSecurityInfo error = %lu\n", dwErrorCode);
          return -1;
}

// First call to LookupAccountSid to get the buffer sizes.
bRtnBool = LookupAccountSidW(
                  NULL,           // local computer
                  pSidOwner,
                  AcctName,
                  (LPDWORD)&dwAcctName,
                  DomainName,
                  (LPDWORD)&dwDomainName,
                  &eUse);

// Reallocate memory for the buffers.
AcctName = (LPWSTR)GlobalAlloc(
          GMEM_FIXED,
          dwAcctName * sizeof(wchar_t));

// Check GetLastError for GlobalAlloc error condition.
if (AcctName == NULL) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();
          wprintf(L"GlobalAlloc error = %lu\n", dwErrorCode);
          return -1;
}

    DomainName = (LPWSTR)GlobalAlloc(
           GMEM_FIXED,
           dwDomainName * sizeof(wchar_t));

    // Check GetLastError for GlobalAlloc error condition.
    if (DomainName == NULL) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();
          wprintf(L"GlobalAlloc error = %lu\n", dwErrorCode);
          return -1;

    }

    // Second call to LookupAccountSidW to get the account name.
    bRtnBool = LookupAccountSidW(
          NULL,                   // name of local or remote computer
          pSidOwner,              // security identifier
          AcctName,               // account name buffer
          (LPDWORD)&dwAcctName,   // size of account name buffer
          DomainName,             // domain name
          (LPDWORD)&dwDomainName, // size of domain name buffer
          &eUse);                 // SID type

    // Check GetLastError for LookupAccountSidW error condition.
    if (bRtnBool == FALSE) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();

          if (dwErrorCode == ERROR_NONE_MAPPED)
              wprintf(L"Account owner not found for specified SID.\n");
          else
              wprintf(L"Error in LookupAccountSidW.\n");
          return -1;

    } else if (bRtnBool == TRUE)

        // Print the account name.
        wprintf(L"Account owner = %s\n", AcctName);

    return 0;
}
