# proclim
[WinDivert](https://github.com/basil00/WinDivert)-based per-process network bandwidth limiter for Windows


proclim is a simple CLI tool that allows you to limit the network bandwidth of specific processes on your Windows machine.


### How to build
- Get [CMake](https://cmake.org/)
    - Install it (select the option to add it to the system PATH)
- Get [WinDivert](https://github.com/basil00/WinDivert/releases)
    - Download the latest release and extract it
    - Copy `include/windivert.h` to `proclim/include/`
    - Copy `x64/WinDivert.lib` to `proclim/lib/`
- Get [CLI11](https://github.com/CLIUtils/CLI11/releases)
    - Download the latest `CLI11.hpp` file and copy it to `proclim/include/`
- Build the app
    - Open a terminal and cd into the `proclim` folder
    - Run ```cmake --preset=x64-release -B build/x64-release && cmake --build build/x64-release --config Release``` to build the app
- Go back to the extracted WinDivert folder
    - Copy `x64/WinDivert.dll` to `proclim/build/x64-release/Release/`
    - Copy `x64/WinDivert64.sys` to `proclim/build/x64-release/Release/`


### How to use
- Run the app using a terminal with administrator privileges (required for WinDivert)
- Use command line options to specify which processes to limit and the desired bandwidth limits (`proclim --help` for details)