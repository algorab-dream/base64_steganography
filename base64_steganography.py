import os
import sys
import codecs
import argparse

alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

parser = argparse.ArgumentParser()

parser.add_argument('-v', "--verbose", help="Verbose mode", action="store_true")
parser.add_argument('-s', '--support', help="Support text that will be encoded", default=None, type=str)
parser.add_argument('-t', '--text', help="Text to be hidden", default=None, type=str)
parser.add_argument('-o', '--output', help="Output address of the encoded text", default=None, type=str)
parser.add_argument('-d', "--decode", help="Extract hidden text from a base64 file (--text)", action="store_true")

args = parser.parse_args()

if not (args.decode):

    if ((args.text == None) or (args.support == None)):
        print("[-] Text and support files must be specified.")
        sys.exit(1)

    if args.verbose:
        print('[*] Opening files...')

    if not (os.path.exists(args.support)):
        print("[-] Error : Following file does not exist : " + args.support)
        sys.exit(1)

    if not (os.path.exists(args.text)):
        print("[-] Error : Following file does not exist : " + args.text)
        sys.exit(1)

    try:
        txtSupport = open(args.support, "r")
    except:
        print("[-] Error while opening file : " + args.support)
        sys.exit(1)

    try:   
        txtSteg = open(args.text, "r")
    except:
        print("[-] Error while opening file : " + args.text)
        sys.exit(1)

    bitsTextList = []
    bitsStegList = []
    bitsText = ''
    bitsSteg= ''

    if args.verbose:
        print('[*] Converting texts to bits...')

    line = txtSteg.readline()

    while line:
        bitsStegList.append(bin(int((line.encode('ascii')).hex(), 16))[2:].zfill(8*len(line)))
        line = txtSteg.readline()

    txtSteg.close()

    bitsSteg = ''.join(bitsStegList)

    line = txtSupport.readline()

    while line:
        bitsTextList.append(bin(int((line.encode('ascii')).hex(), 16))[2:].zfill(8*len(line)))
        line = txtSupport.readline()

    txtSupport.close()

    bitsText = ''.join(bitsTextList)

    if (len(bitsText)/2 <= len(bitsSteg)):
        print("[-] Text too long for this support.")
        sys.exit(1)

    base64Parts = []

    bitsTextProcess = list(bitsText)

    bitsStegProcess = list(bitsSteg)

    if args.verbose:
        print('[*] Hiding text (this step might be long)...')

    size = len(bitsTextProcess)//24
    length = 24*size+8

    while (len(bitsStegProcess) != 0):
        try:
            if (len(bitsStegProcess)%4==0):
                base64slice = ["=="]
                for i in range(length):
                    base64slice.append(bitsTextProcess[0])
                    bitsTextProcess = bitsTextProcess[1:]
                for bit in (bitsStegProcess[:4]):
                    base64slice.append(bit)
                bitsStegProcess = bitsStegProcess[4:] 
                base64Parts.append(base64slice)
            else:
                base64slice = ["="]
                for i in range(length+8):
                    base64slice.append(bitsTextProcess[0])
                    bitsTextProcess = bitsTextProcess[1:]
                for bit in (bitsStegProcess[:2]):
                    base64slice.append(bit)
                bitsStegProcess = bitsStegProcess[2:]
                base64Parts.append(base64slice)
        except:
            base64Parts = []
            bitsTextProcess = list(bitsText)
            bitsStegProcess = list(bitsSteg)
            size -= 1
            length = 24*size+8

    print('[+] Text hidden.')

    if args.verbose:
        print('[*] Converting the end of support text...')

    if (len(bitsTextProcess)%6==0):
        base64slice=[]
        for bit in bitsTextProcess:
            base64slice.append(bit)
        base64Parts.append(base64slice)
    elif(len(bitsTextProcess)%6==2):
        base64slice=["=="]
        for bit in bitsTextProcess:
            base64slice.append(bit)
        for i in range(4):
            base64slice.append('0')
        base64Parts.append(base64slice)
    else:
        base64slice=["="]
        for bit in bitsTextProcess:
            base64slice.append(bit)
        for i in range(2):
            base64slice.append('0')
        base64Parts.append(base64slice)

    if args.verbose:
        print('[*] Converting bits to ASCII strings...')

    base64lines = []

    for bitLine in base64Parts:
        line = []
        bitLineProcess = bitLine
        end = None
        if (bitLineProcess[0] != '0') and (bitLineProcess[0] != '1'):
            end = bitLineProcess[0]
            bitLineProcess = bitLineProcess[1:]
        while(len(bitLineProcess) != 0):
            char = ''
            for i in range(6):
                char += bitLineProcess[0]
                bitLineProcess = bitLineProcess[1:]
            line.append(alphabet[int(char, 2)])
        if (end != None):
            line.append(end)
        base64lines.append(line)

    if args.verbose:
        print('[+] Build.')

    if (args.output != None):
        if args.verbose:
            print('[*] Writing base64 text at ' + args.output + '...')
        try:
            output = open(args.output,'w')
            for line in base64lines:
                output.write(''.join(line))
                output.write('\n')
            output.close()
            print("[+] Encoded string written at : " + args.output)
        except:
            print("[-] Error while creating ouput file.")
            sys.exit(1)
        sys.exit()
    else:
        print("[+] Encoded string : ")
        for line in base64lines:
            print(''.join(line))
        sys.exit()

else:

    if args.verbose:
        print('[*] Opening files...')

    if not (os.path.exists(args.text)):
        print("[-] Error : Following file does not exist : " + args.text)
        sys.exit(1)

    try:   
        text = open(args.text, "r")
    except:
        print("[-] Error while opening file : " + args.text)
        sys.exit(1)

    line = text.readline()
    bitLines = []
    bits = ''
    while line:
        if (line[-2] == '='):
            bitText = ['==']
            for i in range(len(line) - 2):
                for k in range(len(alphabet)):
                    if alphabet[k] == line[i]:
                        bitText.append(bin(k)[2:].zfill(6))
            bitLines.append(bitText)
        elif (line[-1] == '='):
            bitText = ['=']
            for i in range(len(line) - 1):
                for k in range(len(alphabet)):
                    if alphabet[k] == line[i]:
                        bitText.append(bin(k)[2:].zfill(6))
            bitLines.append(bitText)
        line = text.readline()
    text.close()

    if args.verbose:
        print('[*] Extracting data...')

    for line in bitLines:
        lastchar = line[-1]
        pad = line[0]
        if pad == '==':
            for bit in lastchar[-4:]:
                bits += bit
        else:
            for bit in lastchar[-2:]:
                bits += bit
    
    print("[+] Data extracted.")

    if args.verbose:
        print('[*] Converting bits to ASCII string...')

    try:
        plainText = codecs.decode(hex(int(bits, 2))[2:], 'hex').decode('ascii')
    except:
        bits = bits[:-2]
        try:
            plainText = codecs.decode(hex(int(bits, 2))[2:], 'hex').decode('ascii')
        except:
            bits = bits[:-2]
            try:
                plainText = codecs.decode(hex(int(bits, 2))[2:], 'hex').decode('ascii')
            except:
                print("[-] Error while converting bits to ASCII string.")
                sys.exit(1)

    if (args.output != None):
        if args.verbose:
            print('[*] Writing extracted text at ' + args.output + '...')
        try:
            open(args.output,'w').write(plainText)
            print("[+] Encoded string written at : " + args.output)
        except:
            print("[-] Error while creating ouput file.")
            sys.exit(1)
        sys.exit()
    else:
        print("[+] Extracted text : ")
        print(plainText)
        sys.exit()