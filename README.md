# DarkLoadLibrary

`LoadLibrary` for offensive operations.

### How does it work?

https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/

### Usage

```C
DARKMODULE DarkModule = DarkLoadLibrary(
    LOAD_LOCAL_FILE, // control flags
    L"TestDLL.dll", // local dll path, if loading from disk
    NULL, // dll buffer to load from if loading from memory
    0, // dll size if loading from memory
    NULL // dll name if loaded from memory
);
```

#### Control Flags:
-   LOAD_LOCAL_FILE - Load a DLL from the file system.
-   LOAD_MEMORY - Load a DLL from a buffer.
-   NO_LINK  - Don't link this module to the PEB, just execute it.

#### DLL Path:

This can be any path that `CreateFileW` will open.

### DLL Buffer:

This argument is only needed when `LOAD_MEMORY` is set. In that case this argument should be the buffer containing the DLL.

#### DLL Size:

This argument is only needed when `LOAD_MEMORY` is set. In that case this argument should be the size of the buffer containing the DLL.

#### DLL Name:

This argument is only needed when `LOAD_MEMORY` is set. In that case this argument should be the name which the DLL should be set in the PEB under.

### Considerations

The windows loader is very complex and can handle all the edge case's and intricacies of loading DLLs. There are going to be edge case's which I have not had the time to discover, reverse engineer and implement. So there's going to be DLLs that this loader simply will not work with.

That being said I plan on making this loader as complete as possible, so please open issue's for DLLs that are not correctly loaded.
