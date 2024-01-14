// taken and corrected from https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812
#include <Windows.h>
#include <assert.h>
// TODO macro check for utf-16
// TODO JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

int main(int argc, char** argv)
{
  HANDLE job = CreateJobObject(NULL, NULL);

  // JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = { };
  // info.BasicLimitInformation.LimitFlags =
  //                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  // SetInformationJobObject(hJob,
  //       JobObjectExtendedLimitInformation,
  //       &info, sizeof(info));

  SIZE_T size;
  InitializeProcThreadAttributeList(NULL, 1, 0, &size);
  PPROC_THREAD_ATTRIBUTE_LIST p = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(sizeof(char) * size);

  InitializeProcThreadAttributeList(p, 1, 0, &size);
  UpdateProcThreadAttribute(p, 0,
    PROC_THREAD_ATTRIBUTE_JOB_LIST,
    &job, sizeof(job),
    NULL, NULL);

  wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";
  STARTUPINFOEXW siex = {};
  siex.lpAttributeList = p;
  siex.StartupInfo.cb = sizeof(siex);
  PROCESS_INFORMATION pi;

  CreateProcessW(cmd, cmd, NULL, NULL, FALSE,
    CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT,
    NULL, NULL, &siex.StartupInfo, &pi);

  // Verify that the process is indeed in the job object.
  BOOL isInJob;
  IsProcessInJob(pi.hProcess, job, &isInJob);
  assert(isInJob);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  free(p);
  CloseHandle(job);

  return 0;
}
