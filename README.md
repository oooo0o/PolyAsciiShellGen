# PolyAsciiShellGen: alphanumeric shellcode encoder

PolyAsciiShellGen is a simple alphanumeric shellcode encoder coded in C. This program automates the Riley Eller's technic [1] to bypass MSB data filters, for buffer overflow exploits, on Intel platforms. It provides extra functionnalities such as the NOP sleed generation and the size optimisation. It takes a shellcode to encode in entry and return a printable shellcode directly useable. 



## Synopsis

Getting and building the PolyAsciiShellGen program.

``` 
$ git clone https://github.com/VincentDary/PolyAsciiShellGen.git
$ cd PolyAsciiShellGen
$ make && make clean
```
Usage.

```
$ ./PolyAsciiShellGen
usage: PolyAsciiShellGen <esp offset> <nop sleed factor N * 4 NOPS> <shellcode "\xOP\xOP"...>
```

## Description

 PolyAsciiShellGen takes a shellcode in entry, it encodes the shellcode in ASCII format, and then it builds a decoder/loader with printable opcodes which wraps the encoded shellcode. This program automates and optimizes the shellcode encoding process in ASCII format describe by Riley Eller in this paper [2]. Moreover, this article shows how to build a machine code which decodes and loads a encoded shellcode with a reduce set of x86 printable opcodes. The resulting machine code in printable format, realises the following operations to load, and to execute the original shellcode in the memory:


"move the stack pointer just past the ASCII code, decode 32-bits of the original sequence at a time, and push that value onto the stack. As the decoding progresses, the original binary series is "grown" toward the end of the ASCII code. When the ASCII code executes its last PUSH instruction, the first bytes of the exploit code are put into place at the next memory address for the processor to execute. "
Riley Eller


Below, an illustration of the shellcode loading techique realized by the shellcode loader.

```
 1)      Low addresse      2)      Low addresse     3)      Low addresse
      |                |        |                |       |                |
eip-->|----------------|        |----------------|       |----------------|
      |                |        |                |       |                |
      |    Shellcode   |        |    Shellcode   |       |    Shellcode   |
      |     loader     |        |     loader     |       |     loader     |
      |                |  eip-->|                |       |                |
      |                |        |                |       |                |
      |                |        |                |  eip  |                |
      |----------------|        |----------------|    -->|----------------|
      |                |        |                |  esp  |                |    
      |                |        |                |       |                |    
      |                |        |                |       |                |
      |                |  esp-->|----------------|       |     Builded    |
      |                |        |                |       |    Shellcode   |
      |                |        |     decoded    |       |                |
      |                |        |    shellcode   |       |                |
esp-->|                |        |                |       |                |
      |                |        |----------------|       |----------------|
         High adresse              High adresse             High adresse

```



