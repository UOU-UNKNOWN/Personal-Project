from pwn import *
from utility import *

class BinaryAnalyzer:

    ARCH_TYPE = {0x03:"i386", 0x3E:"amd64", 0x28:"arm", 0xB7:"aarch64"}
    OS_ABI = {0x0:"System-V", 0x3:"Linux"}
    CLASS = {0x1:"32", 0x2:"64"}
    ENDIAN = {0x1:"little", 0x2:"big"}
    OBJ_TYPE = {0x1:"Relocatable", 0x2:"Executable", 0x3:"Shared Object", 0x4:"Core"}
    PH_TYPE = {0x0:"NULL", 0x1:"LOAD", 0x2:"DYNAMIC", 0x3:"INTERP", 0x4:"NOTE", 0x5:"SHLIB",
               0x6:"PHDR", 0x7:"TLS", 0x6474e550:"GNU_EH_FRAME", 0x6474e551:"GNU_STACK", 0x6474e552:"GNU_RELRO",
               0x6474e553:"GNU_PROPERTY", 0x70000001:"ARM_EXIDX", }
    SH_TYPE = {0x0:"NULL", 0x1:"PROGBITS", 0x2:"SYMTAB", 0x3:"STRTAB", 0x4:"RELA", 0x5:"HASH", 0x6:"DYNAMIC",
               0x7:"NOTE", 0x8:"NOBITS", 0x9:"REL", 0xa:"SHLIB", 0xb:"DYNSYM", 0xe:"INIT_ARRAY", 0xf:"FINI_ARRAY",
               0x10:"PREINIT_ARRAY", 0x11:"GROUP", 0x12:"SYMTAB_SHNDX", 0x13:"RELR", 0x6ffffff6:"GNU_HASH", 0x6fffffff:"VERSYM",
               0x6ffffffe:"VERNEED", 0x6ffffffd:"VERDEF", 0x70000001:"ARM_EXIDX", 0x70000003:"ARM_ATTRIBUTES",}
    DISASR = r"([0-9a-f]{1,}):\s{1,}(\s([A-Za-z0-9]+\s)+)[ ]{1,}([.a-z0-9]{2,})([0-9a-z\+\[\] A-Z:]{0,})[, ]{0,}([0-9a-z+-\[\] A-Z:]{0,})"
    PH_TYPE.update({value:key for key,value in PH_TYPE.items()})
    SH_TYPE.update({value:key for key,value in SH_TYPE.items()})
    def __init__(self, path):
        try:
            self.file = open(path, "rb")
        except FileNotFoundError:
            raiseErr(f"file not found. {path}")
        
        self.fheader  = {}
        self.pheader  = []
        self.sheader  = {}
        self.security = {}
        self.sdata    = {}
        self.symbols = {}
        self.addrToCode = {}

        e = ELF(path)
        self.plt = e.plt
        self.got = e.got

        self.baseAddr = 0xFFFFFFFFFFFFFFFF

        self.readFileHeader()
        self.readProgramHeader()
        self.readSectionHeader()
        self.readSection()
        self.checkSecurity()

    def printAll(self):
        for i in self.__dict__.keys():
            print("%-28s"%i, self.__dict__[i])
    
    def readFileHeader(self):
        if self.file.read(4)!=b"\x7F\x45\x4C\x46":
            raiseErr("Not a ELF Format.")

        self.fheader["class"] = u8(self.file.read(1))        # 32-bit vs 64-bit
        context.bits = 64 if self.fheader["class"]==2 else 32
        self.fheader["data"] = u8(self.file.read(1))         # endian
        self.fheader["version"] = u8(self.file.read(1))
        self.fheader["osabi"] = u8(self.file.read(1))        # system ABI
        self.fheader["abiversion"] = u8(self.file.read(1))
        self.file.read(7) # padding

        self.fheader["type"] = u16(self.file.read(2))        # object file type

        self.fheader["machine"] = u16(self.file.read(2))     # architecture
        context.arch = self.ARCH_TYPE[self.fheader["machine"]]
        self.fheader["version"] = u32(self.file.read(4))

        if self.fheader["class"] == 1:
            self.fheader["entry"] = u32(self.file.read(4))
            self.fheader["phoff"] = u32(self.file.read(4))
            self.fheader["shoff"] = u32(self.file.read(4))
        elif self.fheader["class"] == 2:
            self.fheader["entry"] = u64(self.file.read(8))
            self.fheader["phoff"] = u64(self.file.read(8))
            self.fheader["shoff"] = u64(self.file.read(8))
        
        self.fheader["flags"] = u32(self.file.read(4))
        self.fheader["ehsize"] = u16(self.file.read(2))
        self.fheader["phentsize"] = u16(self.file.read(2))
        self.fheader["phnum"] = u16(self.file.read(2))
        self.fheader["shentsize"] = u16(self.file.read(2))
        self.fheader["shnum"] = u16(self.file.read(2))
        self.fheader["shstrndx"] = u16(self.file.read(2))

    
    def readProgramHeader(self):
        if self.fheader["phnum"] == 0:
            return
        if self.file.tell() != self.fheader["phoff"]:
            raiseErr("Invalid ELF File.")
        if self.fheader["class"] == 1:
            for _ in range(self.fheader["phnum"]):
                temp = {}
                temp["type"] = u32(self.file.read(4))
                temp["offset"] = u32(self.file.read(4))
                temp["vaddr"] = u32(self.file.read(4))
                temp["paddr"] = u32(self.file.read(4))
                temp["filesz"] = u32(self.file.read(4))
                temp["memsz"] = u32(self.file.read(4))
                temp["flags"] = u32(self.file.read(4))
                temp["align"] = u32(self.file.read(4))
                if temp["type"] == self.PH_TYPE["LOAD"]: self.baseAddr = min(self.baseAddr, temp["vaddr"])
                self.pheader.append(temp)

        elif self.fheader["class"] == 2:
            for _ in range(self.fheader["phnum"]):
                temp = {}
                temp["type"] = u32(self.file.read(4))
                temp["flags"] = u32(self.file.read(4))
                temp["offset"] = u64(self.file.read(8))
                temp["vaddr"] = u64(self.file.read(8))
                temp["paddr"] = u64(self.file.read(8))
                temp["filesz"] = u64(self.file.read(8))
                temp["memsz"] = u64(self.file.read(8))
                temp["align"] = u64(self.file.read(8))
                if temp["type"] == self.PH_TYPE["LOAD"]: self.baseAddr = min(self.baseAddr, temp["vaddr"])
                self.pheader.append(temp)
    def readSectionHeader(self):
        self.shtemp = []
        self.orgOff = self.file.tell()
        self.file.seek(self.fheader["shoff"])
        if self.fheader["class"] == 1:
            for _ in range(self.fheader["shnum"]):
                temp = {}
                temp["name"] = u32(self.file.read(4))
                temp["type"] = u32(self.file.read(4))
                temp["flag"] = u32(self.file.read(4))
                temp["addr"] = u32(self.file.read(4))
                temp["offset"] = u32(self.file.read(4))
                temp["size"] = u32(self.file.read(4))
                temp["link"] = u32(self.file.read(4))
                temp["info"] = u32(self.file.read(4))
                temp["align"] = u32(self.file.read(4))
                temp["entsize"] = u32(self.file.read(4))
                self.shtemp.append(temp)
        elif self.fheader["class"] == 2:
            for _ in range(self.fheader["shnum"]):
                temp = {}
                temp["name"] = u32(self.file.read(4))
                temp["type"] = u32(self.file.read(4))
                temp["flag"] = u64(self.file.read(8))
                temp["addr"] = u64(self.file.read(8))
                temp["offset"] = u64(self.file.read(8))
                temp["size"] = u64(self.file.read(8))
                temp["link"] = u32(self.file.read(4))
                temp["info"] = u32(self.file.read(4))
                temp["align"] = u64(self.file.read(8))
                temp["entsize"] = u64(self.file.read(8))
                self.shtemp.append(temp)
    
    def readSection(self):
        self.str = []
        for i in range(self.fheader["shnum"]):
            if self.shtemp[i]["type"] == self.SH_TYPE["STRTAB"]:
                self.file.seek(self.shtemp[i]["offset"])
                data = self.file.read(self.shtemp[i]["size"])
                if data.startswith(b"\x00."):
                    for j in range(self.fheader["shnum"]):
                        self.file.seek(self.shtemp[j]["name"]+self.shtemp[i]["offset"])
                        name = b""
                        while True:
                            now = self.file.read(1)
                            if now==b"\x00":break
                            name += now
                        self.sheader[name.decode()] = self.shtemp[j]
                    break
        for key in self.sheader.keys():
            self.file.seek(self.sheader[key]["offset"])
            self.sdata[key] = self.file.read(self.sheader[key]["size"])
            if self.sheader[key]["type"] == self.SH_TYPE["STRTAB"]:
                self.sdata[key] = self.sdata[key].split(b"\x00")

        if ".symtab" in self.sheader.keys(): self.readSymbols(".symtab", ".strtab")
        if ".dynsym" in self.sheader.keys(): self.readSymbols(".dynsym", ".dynstr") 
    def readSymbols(self, tabName, strName):
        symbol_cnt = self.sheader[tabName]["size"]//self.sheader[tabName]["entsize"]
        self.file.seek(self.sheader[tabName]["offset"])
        if self.fheader["class"]==2:
            for _ in range(symbol_cnt):
                temp = {}
                snoff = u32(self.file.read(4))
                origin = self.file.tell()
                self.file.seek(self.sheader[strName]["offset"]+snoff)
                sname = b""
                while True:
                    now = self.file.read(1)
                    if now == b"\x00": break
                    sname += now
                self.file.seek(origin)
                temp["info"] = u8(self.file.read(1))
                temp["other"] = u8(self.file.read(1))
                temp["shndx"] = u16(self.file.read(2))
                temp["value"] = u64(self.file.read(8))
                temp["size"] = u64(self.file.read(8))
                temp["code"] = b""
                temp["disasm"] = None
                if (temp["info"]&0x2==0 and temp["info"]&0x1==0) or temp["value"]==0: continue
                self.symbols[sname.decode()] = temp
        elif self.fheader["class"]==1:
            for _ in range(symbol_cnt):
                temp = {}
                snoff = u32(self.file.read(4))
                origin = self.file.tell()
                self.file.seek(self.sheader[strName]["offset"]+snoff)
                sname = b""
                while True:
                    now = self.file.read(1)
                    if now == b"\x00": break
                    sname += now
                self.file.seek(origin)
                temp["value"] = u32(self.file.read(4))
                temp["size"] = u32(self.file.read(4))
                temp["info"] = u8(self.file.read(1))
                temp["other"] = u8(self.file.read(1))
                temp["shndx"] = u16(self.file.read(2))
                temp["code"] = b""
                temp["disasm"] = None
                if temp["info"]&0x2==0: continue
                self.symbols[sname.decode()] = temp

    def disassemble(self, symbol):
        self.symbols[symbol]["disasm"] = []
        if self.symbols[symbol]["info"]&0x2 == 0: return
        if self.symbols[symbol]["value"]==0 or self.symbols[symbol]["size"]==0: return
        offset = self.symbols[symbol]["value"] - self.baseAddr
        if offset<0:return
        temp = []
        self.file.seek(offset)
        result = disasm(self.file.read(self.symbols[symbol]["size"]), vma=self.symbols[symbol]["value"], arch = self.ARCH_TYPE[self.fheader["machine"]]).split("\n")
        now = 0
        for line in result:
            if line.find("...")!=-1:continue
            tt = []
            match = re.match(self.DISASR, line.strip())
            self.addrToCode[hex(int(match.group(1),16))] = "<main" + (">" if now==0 else f"+{now}>")
            now += len(match.group(2).strip().split(" "))
            tt.append(hex(int(match.group(1),16)))
            tt.append(match.group(2))
            tt.append(match.group(3))
            tt.append(match.group(4))
            try:
                tt.append(match.group(5)+self.getSymbolName(match.group(5)))
            except:
                tt.append(match.group(5))
            try:
                tt.append(match.group(6)+self.getSymbolName(match.group(6)))
            except:
                tt.append(match.group(6))
            temp.append(tt)
        self.symbols[symbol]["disasm"] = temp

    def getSymbolName(self, addr):
        addr = int(addr, 16)
        for symbol in self.symbols.keys():
            if self.symbols[symbol]["value"] <= addr < self.symbols[symbol]["value"]+self.symbols[symbol]["size"]:
                return " <" + symbol + \
                      (">" if self.symbols[symbol]["value"]==addr else "+%d>"%(addr-self.symbols[symbol]["value"]))
        
        for symbol in self.plt.keys():
            if self.plt[symbol]-4 == addr:
                return f" <{symbol}>"
        raise Exception

    def checkSecurity(self):
        self.security["PIE"] = "Enabled" if (self.fheader["type"] == 3) else "Disabled"
        self.security["NX"] = "Disabled"
        for ph in self.pheader:
            if ph["type"]==self.PH_TYPE["GNU_STACK"] and ph["flags"]&0x1==0:
                self.security["NX"] = "Enabled"
                break
        self.security["RELRO"] = "Full RELRO" if ".got.plt" not in self.sheader.keys() else "Partial RELRO"
        self.security["Stack Canary"] = "No Canary"
        if ".strtab" in self.sdata.keys():
            for i in self.sdata[".strtab"]:
                if b"__stack_chk_fail" in i:
                    self.security["Stack Canary"] = "Canary Enabled"
                    break
        else:
            if b"\x64\x48\x8b\x04\x25\x28\x00" in self.sdata[".text"]:
                self.security["Stack Canary"] = "Canary Enabled"