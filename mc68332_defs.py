# @runtime Jython

# mc68332 addr space + mmio regs (TODO) initializer
#
# jython vs pyghidra : ref https://github.com/NationalSecurityAgency/ghidra/issues/8555

# (c) 2026 fenugrec
# GPLv3
#
# Preferably run this immediately after importing the ROM dump, before running auto-analysis or doing any work.
#
# @author: fenugrec
# @category: mc68k

# create one MMIO mem block : uninit, RW and volatile
def mmioblock_helper(base, offs, len, name):
    block = createMemoryBlock(name, toAddr(base + offs), None, len, 0)
    block.setPermissions(1,1,0)
    block.setVolatile(1)
    return


# define MMIO arease and peripheral regs
# TODO : baseaddr should depend on 'MM' bit in SIMCR
def create_ioregs(module_baseaddr = 0xfffff000):
    mmioblock_helper(module_baseaddr, 0xa00, 0x80, 'SIM')
    mmioblock_helper(module_baseaddr, 0xb00, 0x40, 'TPURAM_CTL')
    mmioblock_helper(module_baseaddr, 0xc00, 0x200, 'QSM')
    mmioblock_helper(module_baseaddr, 0xe00, 0x200, 'TPU')
    return

def unused():
    #for some reason the "current directory" for open() is not the script's location.
    script_location = os.path.dirname(sourceFile.getAbsolutePath())
    csv_filename = os.path.join(script_location, devtype_base.regs_csv)

    with open(csv_filename, 'rb') as f:
        reader = csv.DictReader(f)
        for row in reader:
            reg_name = row['reg_name']
            #print reg_name, row['reg_addr']
            reg_addr = int(row['reg_addr'], base=16)
            # create as Primary label
            createLabel(toAddr(reg_addr), reg_name, 1)

def main():
    create_ioregs()
    return


if __name__ == "__main__":
    main()

