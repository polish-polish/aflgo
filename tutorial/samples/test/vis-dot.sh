#!/bin/bash
if [ ! -n "$1" ] ;then
   echo "Please provide the dot directory as 1st argument!"; exit 1
fi
filenames=$(ls $1/*.dot)
for file in ${filenames}
do
{
   dot -Tsvg $file -o ${file/%.dot/.svg}
}
done
