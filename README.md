# PolyAsciiShellGen: alphanumeric shellcode encoder

PolyAsciiShellGen is a simple alphanumeric shellcode encoder coded in C. This program automates the Riley Eller's technic [1] to bypass MSB data filters, for buffer overflow exploits, on Intel platforms. It provides extra functionnalities such as the NOP sleed generation and the size optimisation. It takes a shellcode to encode in entry and return a printable shellcode directly useable. 

## Synopsis

Getting and building the PolyAsciiShellGen program.

```
$ git clone https://github.com/VincentDary/PolyAsciiShellGen.git
$ cd PolyAsciiShellGen
$ make && make clean
```
