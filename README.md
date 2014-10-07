concolica
=========

Python concolic execution framework for program analysis

Installation
------------

concolica has a handful of dependencies - the reil translation code requires 
capstone to provide disassembly support, the smt code currently supports only
the Microsoft Z3 solver as a backend.

The following should work on Debian based systems:

`sudo apt-get install asciidoc build-essential gettext git libcurl4-openssl-dev python-pip python-dev zlib1g-dev

git clone https://github.com/git/git.git
cd git
make configure
./configure --prefix=/usr
make all
sudo make install
cd ../

git clone https://github.com/c01db33f/reil.git
git clone https://github.com/c01db33f/smt.git

git clone https://github.com/aquynh/capstone.git
cd capstone
./make.sh
sudo ./make.sh install
cd bindings/python
sudo python ./setup.py install
cd ../../../

sudo pip install termcolor

git clone https://git01.codeplex.com/z3
cd z3
autoconf
./configure
python scripts/mk_make.py
cd build
make -j 8
sudo make install
cd ../../`

Then add the following to your .bash_aliases

`export PYTHONPATH=$PYTHONPATH:/path/to/concolica/smt/and/reil
export VDB_EXT_PATH=/path/to/conolica/vdb`


Usage
-----

All depends what you want to use it for... See the examples directory for some
completely undocumented example code. run_state.py is used with a process dump
made using vdb; something like

`c01db33f@ctf$ vdb
vdb> exec my_program
vdb> bp program.main
vdb> go
vdb> dump_state -a=x86_64 -f=dump.cc
vdb> quit

c01db33f@ctf$ ./run_state.py`

test_trace.py is used to validate the REIL translation code against an execution 
trace made using vdb; something like

`c01db33f@ctf$ vdb
vdb> exec my_program
vdb> bp my_program.main
vdb> go
vdb> save_trace -a=x86_64 -f=output.trace
^C
vdb> quit

c01db33f@ctf$ ./test_trace.py -f=output.trace`




