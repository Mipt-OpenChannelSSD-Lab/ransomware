# Custom ransomware-like software for linux

How to build:

```shell
$ git clone git@github.com:Mipt-OpenChannelSSD-Lab/ransomware.git
$ cd ransomware
$ sudo apt install libssl-dev
$ mkdir build
$ cmake -S . -B build
$ cmake --build build
```

How to encrypt:
```shell
$ echo "From ransomware directory"
$ ./build/ransomware --root=#<root directory for encryption>#
```

How to decrypt:
```shell
$ echo "From ransomware directory"
$ ./build/ransomware --root=#<root directory for decryption># -d
```
