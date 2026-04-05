# different strategy : copy chunk inside existing block
# May need some prior manual work to change block types to Initialized, either del + recreate (easiest) or
# 
# mem = currentProgram.getMemory()
# getMemoryBlock(toAddr('0xa0000800'))
# mem.convertToInitialized( ...
src=askAddress("src addr","src addr")
len=askInt("src len","len")
dest=askAddress("Destination","dest addr")

data=getBytes(src, len)
setBytes(dest, data)
