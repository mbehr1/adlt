#!/bin/sh
# call with two parameters:
# 1. path to search in
# 2. path of adlt executable

$2 --version

# iterate through all dirs
echo "searching in $1"
find $1 -type d | while read dir; do
  # exclude .git folders
  if [[ $dir == *".git"* ]]; then
    #echo "skipping $dir"
    :
  else
    # check if dir contains .dlt files
    if [ -n "$(ls -A $dir/*.dlt 2>/dev/null)" ]
    then
        #echo "$dir has dlt files"
        # determine nr of lcs via adlt
        nr_of_lcs=$($2 convert $dir/*.dlt | grep --binary-files=text -oE 'have [0-9]+ lifecycle' | grep --binary-files=text -oE '[0-9]+')
        echo "'$dir' has $nr_of_lcs lcs"
    fi
  fi
done
