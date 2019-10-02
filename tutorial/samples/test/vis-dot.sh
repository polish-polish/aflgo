#!/bin/bash
filenames=$(ls ./temp/dot-files/*.dot)
for file in ${filenames}
do
{
   dot -Tsvg $file -o ${file/%.dot/.svg}
}
done
