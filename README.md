# Vaccinator
Inject a DLL into every process, look for new process to hook every 0.5s.
The DLL will hook some NTDLL functions to hide some process from enumeration (effectively hidding it from the Task Manager and other such program).
It will also hide some files.
Creating a file called "StopTheHacks.Please" at the root of the C drive will disable the DLLs as long as the file exists. 
