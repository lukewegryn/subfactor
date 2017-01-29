# Subfactor

Subfactor is a tool used in Windows x86 32-bit exploit development to encode an Egghunter using a set of known good characters. It uses the EAX register to perform the relative ESP calculation, as well as the arithmatic for decoding the egghunter.

## Usage

```python
python subfactor [-h|-a] <32 bit hex egghunter> <offset from ESP>

[-h|-a] - hex or assembly output
<32 bit egghunter> : The egghunter you want to encode (!mona egghunter -t w00t) with quotes included
<offset from ESP> : Address you WANT ESP to point to - Address ESP IS pointing to
```

## Example

My egghunter is : "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

**<32 bit egghunter>** : `"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"`

ESP is pointing to : 0x1034E1EA

I want ESP to point to : 0x1035FFEC

0x1035FFEC - 0x1034E1EA = 0x11E02

**<offset from ESP>** : `"\x01\x1E\x02"`

Therefore:

```bash
python subfactor -h "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7" "\x01\x1E\x02"
```

```




