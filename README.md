# Adafruit nRFCrypto

Adafruit Arduino Cryptography Library using hardware-accelerated ARM CryptoCell CC310 on nRF52-based Bluefruit. CryptoCell CC310 is only available on nRF52840 therefore nRF52832 is not supported by this library.

Although this library license is MIT, it uses ARM precompiled static library, which has its own [licence here](src/cortex-m4/license.txt). Please make sure you understand all the license term for files you use in your project. 

## The Fork

This library has been tested with the RAKwireless Arduino BSP for RAK4631 (nRF52840-based) and the [Wisblock](https://github.com/RAKWireless/WisBlock) platform. Since the [RUI3](https://docs.rakwireless.com/RUI3/) platform is not RTOS based, which makes Adafruit libraries difficult, sometimes, to port, I ended up making a smaller, simpler version of this library for RUI3, hosted [here](https://github.com/Kongduino/RUI3_nRFCrypto_AES). It is usually late by a version or two.

### AES 128

A library that calls itself "Crypto" should have Crypto functions – especially since the CC310 has them. So I added a new class, `nRFCrypto_AES`, which provides AES encryption and decryption, ECB, CBC and CTR modes. An example sketch is provided. For the key, and the IV, I am using the library's `Random` object. Might as well make good use of what's available...

![Part1](Part1.jpg)
![Part2](Part2.jpg)

### CHACHA

I have finally managed to add Chacha, and, as far as I can tell, make it work. The library has still some Serial debugging code, which I'll get rid of soon, but it shows what's happening, so all's well. The example encrypts and decrypts a block of 32 bytes (minimum is 64 bytes), then a block of 93 bytes. So far so good.

```
Original [32]:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|2f de cc 2a a1 4e 60 06 ac 5b 7b 39 c3 ac 35 21 | |/..*.N`..[{9..5!|
 1.|09 8d 0a 5d d1 01 2c 16 47 0b e0 27 97 88 db 54 | |...]..,.G..'...T|
   +------------------------------------------------+ +----------------+
Round #1: 0..63 / 64
 * rslt = 0x00000000
Chacha Encoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|53 0e d3 de 01 d3 9e 8e a8 59 0c 47 7c 30 bc e2 | |S........Y.G|0..|
 1.|1a 33 63 d9 e5 e0 ea d3 d8 41 b1 5c b3 3a 41 79 | |.3c......A.\.:Ay|
 2.|00 00 00 00 09 00 00 01 a5 a5 a5 a5 07 78 02 00 | |.............x..|
 3.|03 00 00 00 00 00 00 00 09 04 00 00 51 73 02 00 | |............Qs..|
   +------------------------------------------------+ +----------------+
Round #1: 0..63 / 64
 * rslt = 0x00000000
Chacha Decoded (only the first 32 bytes count):
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|2f de cc 2a a1 4e 60 06 ac 5b 7b 39 c3 ac 35 21 | |/..*.N`..[{9..5!|
 1.|09 8d 0a 5d d1 01 2c 16 47 0b e0 27 97 88 db 54 | |...]..,.G..'...T|
 2.|00 00 00 00 09 00 00 01 a5 a5 a5 a5 07 78 02 00 | |.............x..|
 3.|03 00 00 00 00 00 00 00 09 04 00 00 51 73 02 00 | |............Qs..|
   +------------------------------------------------+ +----------------+
Enc/Dec roud-trip successful!

Original [93]:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|2f de cc 2a a1 4e 60 06 ac 5b 7b 39 c3 ac 35 21 | |/..*.N`..[{9..5!|
 1.|09 8d 0a 5d d1 01 2c 16 47 0b e0 27 97 88 db 54 | |...]..,.G..'...T|
 2.|48 c4 71 d1 7f 30 ff ca 37 c7 d3 75 68 57 28 06 | |H.q.0..7..uhW(.|
 3.|50 1c c8 27 92 15 0c b2 1f 1a 08 fa 1d 04 1d 66 | |P..'...........f|
 4.|22 51 3a 08 e7 9e ae 15 88 82 c5 63 78 d7 5d 0c | |"Q:........cx.].|
 5.|57 53 2a f9 dd 77 b3 b6 7c b6 d5 26 59          | |WS*..w..|..&Y   |
   +------------------------------------------------+ +----------------+
Round #1: 0..63 / 128
Extra round: 64..92 / 93
 * rslt = 0x00000000
Chacha Encoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|53 0e d3 de 01 d3 9e 8e a8 59 0c 47 7c 30 bc e2 | |S........Y.G|0..|
 1.|1a 33 63 d9 e5 e0 ea d3 d8 41 b1 5c b3 3a 41 79 | |.3c......A.\.:Ay|
 2.|7c d9 ea 25 ce 0b 70 95 d1 32 fe 80 03 c4 e6 30 | ||..%..p..2.....0|
 3.|29 8c 68 8c b9 53 82 76 60 c4 35 1d 22 57 ab a0 | |).h..S.v`.5."W..|
 4.|b7 12 f4 c4 2c be 15 39 17 e4 f6 45 a8 fc 5a 57 | |....,..9...E..ZW|
 5.|93 52 fb 4f 6a 84 ee cf e8 e2 88 38 5b          | |.R.Oj......8[   |
   +------------------------------------------------+ +----------------+
Round #1: 0..63 / 128
Extra round: 64..92 / 93
 * rslt = 0x00000000
Chacha Decoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|2f de cc 2a a1 4e 60 06 ac 5b 7b 39 c3 ac 35 21 | |/..*.N`..[{9..5!|
 1.|09 8d 0a 5d d1 01 2c 16 47 0b e0 27 97 88 db 54 | |...]..,.G..'...T|
 2.|48 c4 71 d1 7f 30 ff ca 37 c7 d3 75 68 57 28 06 | |H.q.0..7..uhW(.|
 3.|50 1c c8 27 92 15 0c b2 1f 1a 08 fa 1d 04 1d 66 | |P..'...........f|
 4.|22 51 3a 08 e7 9e ae 15 88 82 c5 63 78 d7 5d 0c | |"Q:........cx.].|
 5.|57 53 2a f9 dd 77 b3 b6 7c b6 d5 26 59          | |WS*..w..|..&Y   |
   +------------------------------------------------+ +----------------+
Enc/Dec roud-trip successful!
```
