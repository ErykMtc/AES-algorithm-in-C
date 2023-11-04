AES
===

This is an implementation of the AES (Advanced Encryption Standard) algorithm in C. The project provides both a standard version and a parallelized version using OpenMP.

# Usage

Compile the standard version (using GCC): 
```shell
gcc aes.c main.c -o main.exe
```

Compile the parallelized version (using GCC and OpenMP): 
```shell
gcc -fopenmp aes.c main.c -o main.exe
```

Run:
```shell
./main
```
