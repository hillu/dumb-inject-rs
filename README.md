# Simple DLL injection demo in Rust

This repository produces a simple, self-contained DLL that can "inject itself" into other processes using the classic `CreateRemoteThread+LoadLibrary` method. It was written for self-education and is provided as-is in the hope that it may be useful to others.

It can be invoked as follows:

``` console
PS C:\Users\user> get-process notepad

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    246      14     3044      17096       0.13   8064   1 notepad

PS C:\Users\user> rundll32 dumb_inject.dll,inject 8064
```

If everything went well, a message box informing the user that the "DLL was injected successfully." After that, a `cmd.exe` is launched. Using Process Explorer, we can verify that the `cmd.exe` is a child process of the process we injected the DLL into.

## License

GNU General Public License, version 3

## Author

- Hilko Bengen <<bengen@hilluzination.de>>
