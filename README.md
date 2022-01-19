# Famine
Educational virus.

:warning: PLEASE DON'T BE STUPID: DO NOT RUN THIS ON YOUR SYSTEM. :warning:

# Notes : 

A simple make will create a virus spreading only in /tmp/test and /tmp/test2

However make bonus will recursively infect EVERY binary file on the system. Use with caution.

# How does it work

The virus will parse executables, and infect either the data segment or the text segment.

* It will inject it's own source code into those binaries and a redirection to the old code.
* Will add my signature to the binary, hence the "tagging virus" title
* Opens a shell with permissions of the user launching the infected binary || virus and makes it available on port 4219.

This means that for instance if you run the virus, from there on launching any binary on your system will infect all the other binaries.

So when ls gets infected every time you'll do a "ls", you're infecting your whole system again and opening a shell backdoor with your current permissions availble on your network.

# Todo: 

* replace placeholder shellcode by infectious one ✔️
* recursive infection from root
* make virus create a network backdoor on system ✔️
* forbid execution when prog called "antivirus" is running ✔️

# Run in docker
```
./run.sh
docker exec -it famine /bin/bash 
cd /famine; make
```
# Run locally
```
cd srcs; make
```
