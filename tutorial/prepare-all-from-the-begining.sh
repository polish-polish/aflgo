#!/bin/bash
sudo apt-get update
sudo apt-get install dot python2-pip
pip install networkx pydot pydotplus
sudo apt-get install python3 python3-dev python3-pip
#sudo pip3 install --upgrade pip
#if accidentially ran pip upgrade then
#wget https://files.pythonhosted.org/packages/a8/1e/293736e7e6e27af6f2a3768fe1bd527dddb67bfb134a4ee282a48214a1b0/networkx-1.11-py2.7.egg#md5=314fde21a33ad8f6753d7a06315722cc
#sudo python2.7 /usr/local/lib/python2.7/dist-packages/easy_install.py networkx-1.11-py2.7.egg
##sudo python2.7 /usr/local/lib/python2.7/dist-packages/easy_install.py -m networkx
#this will reset python2.7 pip as default
#sudo pip uninstall networkx
#sudo pip install networkx

:<<!
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. A future version of pip will drop support for Python 2.7. More details about Python 2 support in pip, can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support
WARNING: The directory '/home/yangke/.cache/pip' or its parent directory is not owned or is not writable by the current user. The cache has been disabled. Check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Collecting networkx
  Downloading networkx-2.2.zip (1.7 MB)
     |████████████████████████████████| 1.7 MB 41 kB/s 
Requirement already satisfied: decorator>=4.3.0 in /usr/local/lib/python2.7/dist-packages/decorator-4.4.1-py2.7.egg (from networkx) (4.4.1)
Building wheels for collected packages: networkx
  Building wheel for networkx (setup.py) ... done
  Created wheel for networkx: filename=networkx-2.2-py2.py3-none-any.whl size=1527321 sha256=f381f1748c7e0093ac478ad5d83f079a711bdd52d30c46d97639679c7f7f7fd6
  Stored in directory: /tmp/pip-ephem-wheel-cache-tZUtFz/wheels/df/80/48/106e63760ff0dcd3658613d93c1ecf64301b9261172f2c1acf
Successfully built networkx
Installing collected packages: networkx
Successfully installed networkx-2.2
!

sudo pip3 install networkx pydot pydotplus

wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main"
sudo apt-get update
sudo apt-get install -y clang-4.0

sudo ln -s /usr/lib/llvm-4.0/bin/clang /usr/bin/clang
sudo ln -s /usr/lib/llvm-4.0/bin/clang++ /usr/bin/clang++
sudo ln -s /usr/lib/llvm-4.0/bin/llvm-config /usr/bin/llvm-config

sudo apt-get install git binutils-gold binutils-dev

# install LLVMgold in bfd-plugins
sudo mkdir /usr/lib/bfd-plugins
#sudo cp /usr/local/lib/libLTO.so /usr/lib/bfd-plugins
#sudo cp /usr/local/lib/LLVMgold.so /usr/lib/bfd-plugins
sudo ln -s /usr/lib/llvm-4.0/lib/libLTO.so /usr/lib/bfd-plugins/libLTO.so
sudo ln -s /usr/lib/llvm-4.0/lib/LLVMgold.so /usr/lib/bfd-plugins/LLVMgold.so


git clone https://github.com/polish-polish/aflgo
sudo patch -p3 < /home/yangke/Program/AFL/aflgo/bak/aflgo/llvm-4.0.1-CFGPrinter.h.patch
