# must split mem regions first to have one self-contained block for _idata
#
mem = currentProgram.getMemory()
bl=mem.getBlocks()
bl_list=list(bl)
selbloc=askChoice("Select target _idata block","entire block will be overwritten ! save your project first !", bl_list,bl_list[0])
mem.convertToInitialized(selbloc,0)

msg="address of _sdata source (should contain %#x bytes):" % selbloc.size
src=askAddress("Source of initialized data",msg)

data=getBytes(src, selbloc.size)
setBytes(selbloc.start, data)