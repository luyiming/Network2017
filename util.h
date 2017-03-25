#ifndef UTIL_H
#define UTIL_H
#include <stdlib.h>

/*--------------------------- colorful printf --------------------------------*/
#define PRINT_Black(str)        printf("\033[0;30m" str "\033[0m")
#define PRINT_Red(str)          printf("\033[0;31m" str "\033[0m")
#define PRINT_Green(str)        printf("\033[0;32m" str "\033[0m")
#define PRINT_Orange(str)       printf("\033[0;33m" str "\033[0m")
#define PRINT_Blue(str)         printf("\033[0;34m" str "\033[0m")
#define PRINT_Purple(str)       printf("\033[0;35m" str "\033[0m")
#define PRINT_Cyan(str)         printf("\033[0;36m" str "\033[0m")
#define PRINT_Light_Gray(str)   printf("\033[0;37m" str "\033[0m")
#define PRINT_Dark_Gray(str)    printf("\033[1;30m" str "\033[0m")
#define PRINT_Light_Red(str)    printf("\033[1;31m" str "\033[0m")
#define PRINT_Light_Green(str)  printf("\033[1;32m" str "\033[0m")
#define PRINT_Yellow(str)       printf("\033[1;33m" str "\033[0m")
#define PRINT_Light_Blue(str)   printf("\033[1;34m" str "\033[0m")
#define PRINT_Light_Purple(str) printf("\033[1;35m" str "\033[0m")
#define PRINT_Light_Cyan(str)   printf("\033[1;36m" str "\033[0m")
#define PRINT_White(str)        printf("\033[1;37m" str "\033[0m")

#endif
