#!/bin/bash
#
# (c) fenugrec 2026
# GPLv3
#
# grab ownership of ghidra project specified in arg1 or current dir if absent
#
#	- looks for the first <projectname>.gpr file
#	- modifies <projectname>/project.prp

u=`whoami`

# use arg1 if defined, else pwd
base_dir="${1:-$(pwd)}"


gpr_file=$(find "$base_dir" -name *.gpr -printf %f -quit)
if [ -z "$gpr_file" ]; then
	echo "no .gpr file found !"
	exit 1
fi

prj_name=${gpr_file%.gpr}
prp_file="$base_dir/${prj_name}.rep/project.prp"
if ! [ -f "$prp_file" ]; then
	echo "$prp_file" not found !
	exit 1
fi

echo Found ghidra project: "$prj_name"
sed "$prp_file" -i -e "/OWNER/s/VALUE=\"[^\"]\+/VALUE=\"$u/"
