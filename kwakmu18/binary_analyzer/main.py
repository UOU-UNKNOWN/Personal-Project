import sys
from binaryanalyzer import BinaryAnalyzer
import tkinter as tk
import ttkbootstrap as ttk
from pwn import *
def changeCode(event):
    scTree.delete(*scTree.get_children())
    selectedItem = stTree.focus()
    symbol = stTree.item(selectedItem).get("text")
    if symbol in ["Functions", "Variables", ""]: return
    context.arch = "amd64" if binary.fheader["class"]==2 else "i386"
    context.bits = 64 if binary.fheader["class"]==2 else 32
    if binary.symbols[symbol]["disasm"]==None: binary.disassemble(symbol)
    for line in binary.symbols[symbol]["disasm"]:
        temp = [line[1], line[3]+" "+line[4]+(" " if line[5]=="" else ", ")+line[5]]
        scTree.insert("", "end", text=hex(int(line[0],16)), values=temp)

def changeSymbolSearch(name, index, mode):
    symbolName = symbolSearch.get()
    stTree.delete(*stTree.get_children())
    fTree = stTree.insert("", "end", text="Functions")
    vTree = stTree.insert("", "end", text="Variables")
    if symbolName=="":
        for symbol in binary.symbols.keys():
            if binary.symbols[symbol]["info"]&0x1:
                stTree.insert(vTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])
            elif binary.symbols[symbol]["info"]&0x2:
                stTree.insert(fTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])  
    for symbol in binary.symbols.keys():
        if symbolName in symbol:
            if binary.symbols[symbol]["info"]&0x1:
                stTree.insert(vTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])
            elif binary.symbols[symbol]["info"]&0x2:
                stTree.insert(fTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])  

if __name__ == '__main__':
    if len(sys.argv)==1:
        print("Usage: python3 main.py [libc_path]")
        exit(-1)
    
    binary = BinaryAnalyzer(sys.argv[1])

    window = ttk.Window()
    window.geometry("1500x600")
    notebook=ttk.Notebook(window, width=1100, height=600)
    notebook.place(x=0,y=0)

    # ----------------------------- File Headers ----------------------------- #
    iTab=tk.Frame(window)
    notebook.add(iTab, text="Information")
    iLabel=ttk.LabelFrame(iTab, text="Information")
    iLabel.place(x=10, y=10, width= 1100, height=320)
    iTree = ttk.Treeview(iLabel, columns = ["A"], displaycolumns=["A"])
    iTree.place(x=10, y=10, width=1060, height=280)

    iTree.column("#0", width=300, anchor="center")
    iTree.heading("#0", text="Field", anchor="center")
    iTree.column("#1", width=400, anchor="center")
    iTree.heading("#1", text="Value", anchor="center")

    arch = binary.ARCH_TYPE[binary.fheader["machine"]] + "-" + binary.CLASS[binary.fheader["class"]] + "-" + binary.ENDIAN[binary.fheader["data"]]
    iTree.insert("", "end", text="Architecture", values=[arch])
    iTree.insert("", "end", text="System ABI", values=[binary.OS_ABI[binary.fheader["osabi"]]])
    iTree.insert("", "end", text="Object Type", values=[binary.OBJ_TYPE[binary.fheader["type"]]])
    iTree.insert("", "end", text="Entry Point", values=[hex(binary.fheader["entry"])])
    iTree.insert("", "end", text="Program Header Offset", values=[hex(binary.fheader["phoff"])])
    iTree.insert("", "end", text="Number of Program Headers", values=[binary.fheader["phnum"]])
    iTree.insert("", "end", text="Size of Program Header", values=[hex(binary.fheader["phentsize"])])
    iTree.insert("", "end", text="Section Header Offset", values=[hex(binary.fheader["shoff"])])
    iTree.insert("", "end", text="Number of Section Headers", values=[binary.fheader["shnum"]])
    iTree.insert("", "end", text="Size of Section Header", values=[hex(binary.fheader["shentsize"])])
    iTree.insert("", "end", text="Section Header String Table Index", values=[hex(binary.fheader["shstrndx"])])
    if binary.fheader["class"]==2: iTree.insert("", "end", text="Interpreter Path", values=[binary.sdata[".interp"].decode()])
    # ----------------------------- File Headers ----------------------------- #

    # ------------------------------- Security ------------------------------- #
    secLabel=ttk.LabelFrame(iTab, text="Securty")
    secLabel.place(x=10, y=330, width=1080, height=240)
    secTree = ttk.Treeview(secLabel, columns = ["A"], displaycolumns=["A"])
    secTree.place(x=10, y=10, width=1060, height=200)

    secTree.column("#0", width=300, anchor="center")
    secTree.heading("#0", text="Field", anchor="center")
    secTree.column("#1", width=400, anchor="center")
    secTree.heading("#1", text="Value", anchor="center")

    for key in binary.security.keys():
        secTree.insert("", "end", text=key, values=[binary.security[key]])
    # ------------------------------- Security ------------------------------- # 
           
    # --------------------------- Program Headers --------------------------- #
    phTab=tk.Frame(window)
    notebook.add(phTab, text="Program Headers")
    phLabel = ttk.LabelFrame(phTab, text="Program Headers")
    phLabel.place(x=10, y=10, width=1080, height=550)
    phTree = ttk.Treeview(phLabel, columns = ["A","B","C","D","E","F","G"], displaycolumns=["A","B","C","D","E","F","G"])
    phTree.place(x=10, y=10, width=1060, height=510)

    phTree.column("#0", width=130, anchor="center")
    phTree.heading("#0", text="Type")
    phTree.column("#1", width=50, anchor="center")
    phTree.heading("#1", text="Flags")
    phTree.column("#2", width=80, anchor="center")
    phTree.heading("#2", text="Offset")
    phTree.column("#3", width=80, anchor="center")
    phTree.heading("#3", text="VirtAddr")
    phTree.column("#4", width=80, anchor="center")
    phTree.heading("#4", text="PhysAddr")
    phTree.column("#5", width=80, anchor="center")
    phTree.heading("#5", text="FileSize")
    phTree.column("#6", width=80, anchor="center")
    phTree.heading("#6", text="MemSize")
    phTree.column("#7", width=80, anchor="center")
    phTree.heading("#7", text="Align")

    for i in range(binary.fheader["phnum"]):
        text = binary.PH_TYPE[binary.pheader[i]["type"]]
        values = []
        flags = ""
        flags += "R" if (binary.pheader[i]["flags"]&4) else ""
        flags += "W" if (binary.pheader[i]["flags"]&2) else ""
        flags += "X" if (binary.pheader[i]["flags"]&1) else ""
        values.append(flags)
        values.append(hex(binary.pheader[i]["offset"]))
        values.append(hex(binary.pheader[i]["vaddr"]))
        values.append(hex(binary.pheader[i]["paddr"]))
        values.append(hex(binary.pheader[i]["filesz"]))
        values.append(hex(binary.pheader[i]["memsz"]))
        values.append(hex(binary.pheader[i]["align"]))
        phTree.insert("", "end", text=text, values=values)
    
    # --------------------------- Program Headers --------------------------- #

    # --------------------------- Section Headers --------------------------- #
    shTab=tk.Frame(window)
    notebook.add(shTab, text="Section Headers")
    shLabel = ttk.LabelFrame(shTab, text="Section Headers")
    shLabel.place(x=10, y=10, width=1080, height=550)
    shTree = ttk.Treeview(shLabel, columns = ["A","B","C","D","E","F","G","H"], displaycolumns=["A","B","C","D","E","F","G","H"])
    shTree.place(x=10, y=10, width=1060, height=510)


    shTree.column("#0", width=270, anchor="center")
    shTree.heading("#0", text="Name")
    shTree.column("#1", width=80, anchor="center")
    shTree.heading("#1", text="Type")
    shTree.column("#2", width=80, anchor="center")
    shTree.heading("#2", text="Flags")
    shTree.column("#3", width=80, anchor="center")
    shTree.heading("#3", text="Addr")
    shTree.column("#4", width=80, anchor="center")
    shTree.heading("#4", text="Offset")
    shTree.column("#5", width=80, anchor="center")
    shTree.heading("#5", text="Size")
    shTree.column("#6", width=80, anchor="center")
    shTree.heading("#6", text="Info")
    shTree.column("#7", width=80, anchor="center")
    shTree.heading("#7", text="AddrAlign")
    shTree.column("#8", width=80, anchor="center")
    shTree.heading("#8", text="EntrySize")

    for i in binary.sheader.keys():
        text = i if i!="" else "NULL"
        values = []
        values.append(binary.SH_TYPE[binary.sheader[i]["type"]])
        flags = ""
        flags += "W" if binary.sheader[i]["flag"]&0x1 else ""
        flags += "A" if binary.sheader[i]["flag"]&0x2 else ""
        flags += "X" if binary.sheader[i]["flag"]&0x4 else ""
        flags += "M" if binary.sheader[i]["flag"]&0x10 else ""
        flags += "S" if binary.sheader[i]["flag"]&0x20 else ""
        flags += "I" if binary.sheader[i]["flag"]&0x40 else ""
        flags += "L" if binary.sheader[i]["flag"]&0x80 else ""
        flags += "O" if binary.sheader[i]["flag"]&0x100 else ""
        flags += "G" if binary.sheader[i]["flag"]&0x200 else ""
        flags += "T" if binary.sheader[i]["flag"]&0x400 else ""
        values.append(flags)
        values.append(hex(binary.sheader[i]["addr"]))
        values.append(hex(binary.sheader[i]["offset"]))
        values.append(hex(binary.sheader[i]["size"]))
        values.append(binary.sheader[i]["info"])
        values.append(hex(binary.sheader[i]["align"]))
        values.append(hex(binary.sheader[i]["entsize"]))
        shTree.insert("", "end", text=text, values=values)
    # --------------------------- Section Headers --------------------------- #

    # ----------------------------- Symbol Table ----------------------------- #
    stTab=tk.Frame(window)
    notebook.add(stTab, text="Symbol Table")
    stLabel = ttk.LabelFrame(stTab, text="Symbol Table")
    stLabel.place(x=10, y=10, width=430, height=550)
    stTree = ttk.Treeview(stLabel, columns = ["A"], displaycolumns=["A"])
    stTree.place(x=10, y=10, width=410, height=470)

    searchLabel = tk.Label(stLabel, text="search: ")
    searchLabel.place(x=10, y=500)

    symbolSearch = tk.StringVar()
    searchEntry = tk.Entry(stLabel, textvariable=symbolSearch)
    searchEntry.place(x=90, y=495, width=330, height=30)
    symbolSearch.trace_add("write", changeSymbolSearch)

    stTree.column("#0", width=300)
    stTree.heading("#0", text="Name")
    stTree.column("#1", width=100)
    stTree.heading("#1", text="addr")

    fTree = stTree.insert("", "end", text="Functions")
    vTree = stTree.insert("", "end", text="Variables")

    for symbol in binary.symbols.keys():
        if binary.symbols[symbol]["info"]&0x1:
            stTree.insert(vTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])
        elif binary.symbols[symbol]["info"]&0x2:
            stTree.insert(fTree, "end", text=symbol, values=[hex(binary.symbols[symbol]["value"])])
    disasmLabel = ttk.LabelFrame(stTab, text="Disasm")
    disasmLabel.place(x=450, y=10, width=640, height=550)

    scTree = ttk.Treeview(disasmLabel, columns = ["A","B"], displaycolumns=["A","B"])
    scTree.place(x=10, y=10, width=620, height=510)

    scTree.column("#0", width=10)
    scTree.heading("#0", text="Address")
    scTree.column("#1", width=100)
    scTree.heading("#1", text="bytecode")
    scTree.column("#2", width=170)
    scTree.heading("#2", text="disasm")
    stTree.bind("<<TreeviewSelect>>", changeCode)
    # ----------------------------- Symbol Table ----------------------------- #

    # ------------------------------- PLT & GOT ------------------------------- #
    pgTab=tk.Frame(window)
    notebook.add(pgTab, text="PLT & GOT")
    pltLabel = ttk.LabelFrame(pgTab, text="PLT")
    pltLabel.place(x=10, y=10, width=530, height=550)
    pltTree = ttk.Treeview(pltLabel, columns = ["A"], displaycolumns=["A"])
    pltTree.place(x=10, y=10, width=510, height=510)
    gotLabel = ttk.LabelFrame(pgTab, text="GOT")
    gotLabel.place(x=550, y=10, width=530, height=550)
    gotTree = ttk.Treeview(gotLabel, columns = ["A"], displaycolumns=["A"])
    gotTree.place(x=10, y=10, width=510, height=510)

    pltTree.column("#0", width=100, anchor="center")
    pltTree.heading("#0", text="PLT")
    pltTree.column("#1", width=100, anchor="center")
    pltTree.heading("#1", text="Address")
    gotTree.column("#0", width=100, anchor="center")
    gotTree.heading("#0", text="GOT")
    gotTree.column("#1", width=100, anchor="center")
    gotTree.heading("#1", text="Address")

    for key in binary.plt.keys():
        pltTree.insert("", "end", text=key, value=hex(binary.plt[key]))
    for key in binary.got.keys():
        gotTree.insert("", "end", text=key, value=hex(binary.got[key]))
    # ------------------------------- PLT & GOT ------------------------------- #
    window.mainloop()