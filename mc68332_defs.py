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

import collections
#from dataclasses import dataclass crap, doesnt work with jython ?
import csv
import os	#for os.path.join
import glob

module_baseaddr = 0xfffff000    # TODO : baseaddr should depend on 'MM' bit in SIMCR

# @dataclass
# class mmio_area():
#     name: str
#     offs: int
#     len: int
# 
class mmio_area():
    def __init__(self, name, base, len):
        self.name = name
        self.base = base
        self.len = len

mc68332_mmio = [
        mmio_area('SIM', 0xa00, 0x80),
        mmio_area('TPURAM_CTL', 0xb00, 0x40),
        mmio_area('QSM', 0xc00, 0x200),
        mmio_area('TPU', 0xe00, 0x200),
        ]

# TODO: implement, or convert to dataclass
devtype = collections.namedtuple('CPU', ['cpu', 'mmio_map', 'regs_csv'])
devlist = [
        devtype('mc68332', mc68332_mmio, 'mc68332regs.csv'),
        ]

def get_builtin_defs():
#for some reason the "current directory" for open() is not the script's location.
    script_location = os.path.dirname(sourceFile.getAbsolutePath())
    flist = [os.path.basename(a) for a in glob.glob(os.path.join(script_location, '*.csv'))]
    fname = askChoice("register defs", "Select register definition CSV file", flist, flist[0])
    return os.path.join(script_location, fname)


# create one MMIO mem block : uninit, RW and volatile
def mmioblock_helper(base, offs, len, name):
    block = createMemoryBlock(name, toAddr(base + offs), None, len, 0)
    block.setPermissions(1,1,0)
    block.setVolatile(1)
    return


# define MMIO areas
# TODO : baseaddr should depend on 'MM' bit in SIMCR
def create_iomap(module_baseaddr = 0xfffff000):
    mmioblock_helper(module_baseaddr, 0xa00, 0x80, 'SIM')
    mmioblock_helper(module_baseaddr, 0xb00, 0x40, 'TPURAM_CTL')
    mmioblock_helper(module_baseaddr, 0xc00, 0x200, 'QSM')
    mmioblock_helper(module_baseaddr, 0xe00, 0x200, 'TPU')
    return

#open definitions file and apply at base address
def define_regs(base, csv_filename):
    with open(csv_filename, 'rb') as f:
        reader = csv.DictReader(f)
        for row in reader:
            offs = int(row['base_offset'], base=16)
            regname = row['regname']

			# create as Primary label
            addr = toAddr(base + offs)
            createLabel(addr, regname, 1)
            setEOLComment(addr, row['comment'])

def main():
    csvfile = get_builtin_defs()
    create_iomap()
    define_regs(module_baseaddr, csvfile)
    return


if __name__ == "__main__":
    main()

