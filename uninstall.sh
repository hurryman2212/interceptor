#!/bin/sh
CMAKE_INSTALL_PREFIX=$(grep "CMAKE_INSTALL_PREFIX" CMakeCache.txt | awk -F'=' '{print $2}')

xargs rm -f <install_manifest.txt || exit 1

grep "/include/" install_manifest.txt | awk '{print length, $0}' | sort -rn | uniq | cut -d" " -f2- | while IFS= read -r line; do
  installed_dir=$(dirname "$line")
  if [ "$installed_dir" != "$CMAKE_INSTALL_PREFIX/include" ]; then
    rmdir "$installed_dir"
  fi
done

rm -f install_manifest.txt
