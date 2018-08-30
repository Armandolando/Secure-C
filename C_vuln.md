# Common C Vulns

## Introduction

This is a collection of the most common C and C++ vulnerabilities and how they can be avoided using a more secure and recent language as Rust

* Buffer Overflow
    * Stack Overflow
    * Heap Overflow

* String Vulns
    * Lenght Vulns
    * Concatenation Vulns
    
* Pointers Vulns
    * Pointers Corruption
    
* Integer Vulns
    * Integer Truncation
    * Integer Overflow
    * Negative Indexing
    
* Heap Managment
    * Null Pointer
    * Use After free() Vuln
    * Unlink Exploit
    * Double free() Vuln

* Format Strings Vulns

* Race Condition 

* Polymorphism
    * Dynamic polymorphism
    * Casting

## Buffer Overflow

### Stack Overflow

#### Vulnerable C Code

Executing this program the input of the  user can excede the dimensions of "buf" and overwrite what has been stored on the stack before it.

```c
#include <stdio.h>

int main() {

    int cookie;

    char buf[10];

    printf("b: %x c: %x\n", &buf, &cookie);

    fgets(buf, 24, stdin);
    printf("Your input: %d\n", strlen(buf));
    if (cookie == 0x41414141)
        printf("you win!\n");
    
    return 0;
}
    
}
```

#### Fixed C Code

In order to protect the return address of the main function  a global and fixed variable "canary" is placed before the buffer that can be overflowed. Before the end of the program there's a condition that verify the integrity of canary variable, if it is overwritten the program exits with code 1.

```c
#include <stdio.h>
#include <stdlib.h>

int check_canary;
int get_canary(void) {
    if (!check_canary) {
        check_canary = rand();
    }

    return check_canary;
}

int main() {

    int canary = get_canary();

    int cookie;

    char buf[10];

    printf("b: %x c: %x\n", &buf, &cookie);

    fgets(buf, 24, stdin);

    if(canary!=check_canary){
        printf("Busted\n");
        exit(1);    
    }

    printf("Doing stuff\n");
    
    return 0;
}

```

#### Alternative in Rust

In Rust cannot be occure a stack overflow because on the stack there's only the pointer to the "buffer"

```rust
use std::io::{self, Read};

fn main() {
    let cookie = 5;
    let mut buffer = [0; 10];
    let stdin = io::stdin();
    stdin.lock().read(&mut buffer).unwrap();
    println!("{:?}", buffer);
    if cookie == 5 {println!("{}", "you win!")}
    
}
```

### Heap Overflow

#### Vulnerable C code

The use of strcpy function can cause a heap overflow

```c
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]){

  char *first, *second, *third;
  
  first = malloc(12);
  second = malloc(12);
  third = malloc(12);
  
  strcpy(first, argv[1]);
  
  free(first);
  free(second);
  free(third);
  
}
```

#### Fixed code in C

The heap overflow can be avoided by using a more reliable function, such as snprintf, instead of strcpy 

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define  MAX_SIZE 12

int main(int argc, char *argv[]){
  
  char *first, *second, *third;
  
  first = malloc(MAX_SIZE);
  second = malloc(MAX_SIZE);
  third = malloc(MAX_SIZE);
  
 
  if(snprintf(first, MAX_SIZE, "%s", argv[1]) >= MAX_SIZE){
    printf("Heap overflow. Aborting\n");
    exit(1);
  }
  
  free(first);
  free(second);
  free(third);
}
```

#### Alternative in Rust

Rust, unless in usecure coding, doesn't permit the managment of the heap 

## String Vulnerabilities

### Lenght Vulnerabilities

#### Vulnerable C code

The use of wcslen instead of sizeof can cause buffer overflow when we alloc memory for a string because the wchar_t size can by 4 byte so size and lenght of a wchar_t string aren't equal 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

int main(){

    wchar_t wide_string[] = L"Hello world, I'm here to exploit you and take the control of your PC\n It's segfault time";

    wchar_t *new_string;

    printf("Length wide_string: %d\nSize wide_string:%d\n", wcslen(wide_string), sizeof(wide_string));

    new_string = (wchar_t *) malloc(wcslen(wide_string));

    wcscpy(new_string, wide_string); 

    new_string = (wchar_t *) realloc(new_string, wcslen(new_string));
    wcscat(new_string, wide_string);
    
    return 0;
} 
```
#### Fixed C code

Length * size is the right amount of memory that a string of wchar_t needs 
 
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

int main(){

    wchar_t wide_string[] = L"Hello world, I'm here to expoit you and take the controll of your PC\n    It's segfault time";

    wchar_t *new_string;

    printf("Length wide_string: %d\nSize wide_string:%d\n", wcslen(wide_string), sizeof(wide_string));

    new_string = (wchar_t *) malloc(wcslen(wide_string)*sizeof(wchar_t));

    wcscpy(new_string, wide_string); 

    new_string = (wchar_t *) realloc(new_string, wcslen(new_string)*sizeof(wchar_t)*2);
    wcscat(new_string, wide_string);
    free(new_string);
    return 0;
} 
```
#### Alternative in Rust

This program shows how Rust change dynamicly the dimension of the string in order to fit all the characters 

```rust
use std::string::String;
use std::char::decode_utf16;

fn main() {
    let buf = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
    
    let mut wide_string = String::from_utf16_lossy(&buf);
    
    let mut new_string = &mut wide_string.clone();
    wide_string.push_str("world京");
    
    new_string.push_str("world");
    
    println!("{:?}", &wide_string);
    println!("{:?}", &new_string);
    println!("{}", &wide_string.len()); //lunghezza in byte
    println!("{}", &new_string.len());
}
```
This program shows how rust panic at compile time when the buffer is not big enought to fit all the characters

```Rust
use std::string::String;

fn main() {
    let mut buf = [0; 1];
    
    let result = {'ß'.encode_utf16(&mut buf);};
    
    println!("{:?}", buf);
}

```

### Concatenation Vulnerabilities

#### Vulnerable C code

The use of strcat and strncat is unsafe because doesn't guarantee the null termination and can cause buffer overflow 

```c
#include <stdio.h>
#include <string.h>

int main(){
    char buf[10];

    char *str = "Segfault time = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    strcat(buf,str); 
    
    return 0;
}

```
```c
#include <stdio.h>
#include <string.h>

int main(){
    char buf[10];

    char *str = "Segfault time =    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    strncat(buf,str,sizeof(buf)+40); 
    printf("Last char of buf: %s\n", buf);
    
    return 0;
}

```
#### Fixed C code

Snprintf is a more secure function because garantees the null termination

```c
#include<stdio.h>
#include<stdlib.h>

int main(){
    int buf_size = 15;
    char *mystr = "Safe use of a safe function";
    char *buf = malloc(buf_size);

    if(snprintf(buf, buf_size, "%s", mystr) >= buf_size){
        buf_size *= 2;
        printf("Not enough space. Trying to double the space\n");
        free(buf);
        buf = malloc(buf_size);

        if(snprintf(buf, buf_size, "%s", mystr) >= buf_size){
            printf("Still not enough space. Aborting\n");
            exit(1);
        }
    }

    printf("There was enough space!\n");
    printf("buf: %s\n", buf);
    return 0;
}
```

#### Alternative in Rust

As before Rust adapt rhe dimension of the string in order to fit the new characters

```rust
use std::string::String;

fn main() {
    
    let mut s1 = String::from("Rust");
    
    s1.push_str(" concatenates");
    
    let s2 = String::from(" strings");
    
    let s3 = s1 + &s2;
    
    let s4 = String::from(" better!");
    
    let s5 = format!("{} {}",s3,s4);
    
    println!("{}", s5);
}
```
## Pointers Vulnerabilities

### Pointers Corruption

#### Vulnerable C code

The function pointer could be modified and point to a malicious function

```c
#include <stdio.h>

int sumNum(int n1, int n2){
    return n1+n2;
}

int main(){

    int (*functionPtr)(int, int);

    functionPtr = &sumNum;

    int sum = (*functionPtr)(1, 2);

    printf("%i\n", sum);

    char buf[10];

    fgets(buf, 30, stdin);

    int seg_sum = (*functionPtr)(2, 3);

    printf("%i\n", seg_sum);
    
    reurn 0;
}
```

#### Fixed C code

```c
#include <stdio.h>

int sumNum(int n1, int n2){
    return n1+n2;
}

int main(){

    int (*functionPtr)(int, int);

    functionPtr = &sumNum;

    int sum = (*functionPtr)(1, 2);

    printf("%i\n", sum);

    char buf[10];

    fgets(buf, sizeof(buf), stdin);

    int seg_sum = (*functionPtr)(2, 3);

    printf("%i\n", seg_sum);
    
    return 0;
}
```
#### Alternative in Rust

Function pointers, in Rust, are used only when it has to comunicate with other languages that don't support closures. 

```rust
fn add_one(n: i32)->i32{
    n+1
}

fn sum_num(f: fn(i32)->i32,n :i32)->i32{
    f(n) + n
}

fn main() {
    let result = sum_num(add_one, 2);
    println!("{}", result);
}
```
## Integer Vulnerabilities

### Integer Truncation and Integer Overflow

#### Vulnerable C code

The association of a value to a variabile with a smaller precision or to an unsigned variable can cause truncation or overflow

```c
#include <stdio.h>
#include <string.h>

int main(){
    int i = -1111111111;
    
    printf("%i\n", i);
    
    short x;
    
    x = i;
    
    printf("%d\n", (short)(x));
    
    unsigned char c1=256;
    unsigned char c2=-6;
    printf("%d,  %d\n",c1+1,c2);
    
    int buffer[1000000];
    short size_int = sizeof(buffer);
    size_t size_size_t = (size_t)(sizeof(buffer));
    
    printf("%d, %ld, %d\n", size_int, size_size_t, sizeof(buffer));
    
    return 0;
}
```
#### Alternative in Rust

This code doesn't compile

```rust
fn main() {
    let x:i16 = -1;
    
    let y:i8 = x;
    println!("{}", y);
}
```
Rust gives you methods to verify if a integer overflow occurs

```rust
fn main() {
    match 255u8.checked_add(1){
        Some(x) => println!("{}", x),
        None => println!("Overflow!"),
    };
    
    let (x, flag) = 255u8.overflowing_add(4);
    
    if flag{
       println!("Overflow! {}", x); 
    } 
}
```
### Negative Indexing

#### Vulnerable C code

C allows negative indexing for an array accessing to memory over the bounds of the array

```c
#include <stdio.h>

int main(){
    int buf[3];
    
    for(int i=0; i<sizeof(buf); i++){
        buf[i] =  i+1;
    }
    
    for(int i=-3; i<5; i++){
        printf("%i, %i\n", i, buf[i]);
    }
    
    return 0;
}
```

#### Fixed C code

```c
#include <stdio.h>
#include <stdlib.h>

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

int main(){
    int buf[3];
    
    for(int i=0; i<NELEMS(buf); i++){
        buf[i] =  i+1;
    }
    
    for(int i=-3; i<5; i++){
        if(i>=0 && i<NELEMS(buf)){
            printf("%i, %i\n", i, buf[i]);
        }
    }
    
    return 0;
}
```

#### Alternative in Rust

Rust doesn't allow negative indexing and promote the use of itarators istead

```rust
fn main() {
    let buf = vec![1, 2, 3];
    
    let buf1 : Vec<i32> = buf.iter().map(|x| x+1).collect();
    
    println!("{:?}", buf1);
}
```

