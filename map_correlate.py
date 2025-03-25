#
# fenugrec 2025

'''
sometimes part of an image may be copied / mapped somewhere else, e.g. idata data copied into ram.

This script tries to guess a likely offset, given 
1- a range in undefined memory (e.g. RAM or unknown) where ghidra found xrefs leading to
2- a range in initialized mem (usually ROM) that has been analyzed and has symbols defined

First strategy:
- reduce undefined-mem symbols list to only code destinations e.g. "SUB_xxxxx"
- reduce initialized mem symbol list to only Functions (auto or manual names)
- iterate through possible offsets ('sliding window'), calculating the # of syms that would 'line up'

Hardcoded for 4-byte pointers, doesn't check alignment
'''

import ghidra.features.base.values.GhidraValuesMap as GVM
#>>> from ghidra.program.model.listing import Program
avals=GVM()
avals.defineAddress("undefined start", currentProgram)
avals.defineAddress("undefind end", currentProgram)
avals.defineAddress("initialized start", currentProgram)
avals.defineAddress("initialized end", currentProgram)

#TODO maybe: use 'validator' feature

vals = askValues('map correlator', None, avals)
ustart = vals.getAddress("undefined start");
uend = vals.getAddress("undefind end");
istart = vals.getAddress("initialized start");
iend = vals.getAddress("initialized end");

if (ustart > uend) or (istart > iend):
    print "Error : start > end"
    exit

wlen = uend.subtract(ustart)
min_offs = ustart.subtract(istart)
min_offs = ustart.subtract(iend)
max_offs = uend.subtract(istart)

sm = currentProgram.getSymbolTable()
scores=[]
best_idx = 0
new_best = 1
# first, filter symlist of initialized data
symb = sm.getSymbolIterator(istart, 1)
s_filtered = []
for s in symb:
    # check only Function symbols, that will fit in the 'undefined' window
    if s.getSymbolType() != ghidra.program.model.symbol.SymbolType.FUNCTION:
        continue
    s_filtered.append(s)

for offs in range(min_offs, max_offs, 2):
    #for each offset, calculate 'score' of matching # of syms
    points = 0
    for s in s_filtered:
        iaddr = s.getAddress()
        if iaddr >= iend:
#        if 0:
            break
        i_pos = iaddr.subtract(istart)
        tgt_addr = ustart.add(offs).add(i_pos)
        usym = sm.getPrimarySymbol(tgt_addr)
#        print "checking " + s.getName() + " @ %x" % tgt_addr.offset + ", i pos %x" % i_pos
        if not usym:
            continue
        if usym.getName().startswith('SUB'):
            points += 1
    scores.append((offs,points))
    if points > new_best:
        new_best = points
        best_idx = len(scores)-1

print "mapping %x to %x: " % (istart.offset, ustart.offset)
print scores[best_idx]
