                Control Flow Guard instrumentation
                                                deroko of ARTeam

Very simple approach  to hunt down indirect calls. Control Flow Guard
can be utilized to inpsect all indirect calls in CFG enabled binaries,
and when CFG is enabled. If it's not enabled, we can utilize 
instrumentation per DLL by replacing it's CFG pointer as described in
this writeup:

http://deroko.phearless.org/cfgicall.txt

So this code will replace (hook) ntdll!LdrpValidateUserCallTarget and
point it to my function which will do instrumentation, it will trigger
__debugbreak() once memory is not in image, for debugging purposes of 
JITed code. Also can be used to hook all indirect calls to some API, 
well, possibilities are endless...

usage:
allowall.bat
inject.exe iexplore.exe (for example)

                                                deroko of ARTeam
                                                