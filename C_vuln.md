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

Rust doesn't allow negative indexing and promote the use of itarators instead 

```rust
fn main() {
    let buf = vec![1, 2, 3];
    
    let buf1 : Vec<i32> = buf.iter().map(|x| x+1).collect();
    
    println!("{:?}", buf1);
}
```
## Heap Managment

### Null Pointer

#### Vulnerable C code 

The use of malloc can create a null pointer that in the embedded systems could be overwritten and point to a malicious function 

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    char buf[10];
    
    for(int i = 0; i<sizeof(buf); i++){
        buf[i] =(char *) malloc(sizeof(buf));
        if(!buf[i]){
            printf("NUll_pointer index: %i\n", i);
            break;
        }
    }
    
    return 0;
}
```
#### Fixed C code

Verify if a null pointer occure and retry the malloc, if fail agian exits the program 

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    char buf[10];
    
    for(int i = 0; i<sizeof(buf); i++){
        buf[i] =(char *) malloc(sizeof(buf));
        if(!buf[i]){
            printf("NUll_pointer index: %i\n", i);
            buf[i] =(char *) malloc(sizeof(buf));
            if(!buf[i]){
            printf("NUll_pointer index: %i\nNot enough space: exit", i);
            exit(1);
            }
            
        }
    }
    
    return 0;
}
```
#### Alternative in Rust

Rust allow the use of raw pointers in safe Rust but they can only dereferenced in unsafe blocks. The raw pointers aren't recomanded because they don't follow the rules of references and allow a immutable and immutable pointer at the same time. Is safe to use only refernces

##### The Rules of References

    * At any given time, you can have either one mutable reference or any number of immutable references.
    * References must always be valid.
    
### Use after free() vulnerability

#### Vulnerable C code

C allows to use pointers after the call of free() funtion on them

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    int *a = malloc(sizeof(int));
    *a = 8;
    printf("%i\n", *a);
    free(a);
    *a = 9;
    printf("%i\n", *a);
    return 0;
}

```
#### Altrnative in Rust

Rust drops a varible every time goes out of scope but it also possible to call the drop function before. After drop the variable can't be used anymore if we try to use it the program panics at 
compile time.

```rust

use std::string::String;

fn still_alive(string: &String){
    println!("{:?}", string);
}

fn main() {
    let x = String::from("Still alive");
    still_alive(&x);
    drop(x);
    println!("{}", x);
}
```
To avoid dangling references, in to compile the program, we have to specify the "lifetime" of a variable. The following code will not compile because string2 doesn't live long enough.

```rust
use std::string::String;

fn longest<'a>(x:&'a str, y:&'a str)->&'a str{
    if x.len() > y.len(){
        x
    } else {
        y
    }
}

fn main() {
    let string1 = String::from("aaaaaaaaaaaaaaa");
    let result;
    {
        let string2 = String::from("bbbbbbbbb");
        result = longest(string1.as_str(),string2.as_str());
    }
    println!("The longest string is {}", result);
}
``` 
In order to compile string1 and string2 must have the same lifetime

```rust
use std::string::String;

fn longest<'a>(x:&'a str, y:&'a str)->&'a str{
    if x.len() > y.len(){
        x
    } else {
        y
    }
}

fn main() {
    let string1 = String::from("aaaaaaaaaaaaaaa");
    let string2 = String::from("bbbbbbbbb");
    let result;
    
    
    result = longest(string1.as_str(),string2.as_str());
    
    println!("The longest string is {}", result);
}

```

### Unlink exploit

#### Vulnerable C code

In this example two small chunks are allocated next to each other. Now we create a fake chunk in the chunk1's data and we modify fd and bk pointers .By overflowing the first chunk we overwrite the flag of the second chunck that indicate if the previous chunk is free. Doing that, after we call free on the second chunck, the unlink macro is triggered and it verifies if the previous chunk is free by reading the overwitten flag of the second chunk and detects the fake chunk indeed.The fake chunk is unlinked in order to merge the consecutive chunks.The unlink execute the following instrutions:

    * P->fd->bk = P->bk 
    * P->bk->fd = P->fd
    
In this case both P->fd->bk and P->bk->fd point to the same location. Now chunk1[3] and chunk[0] point to the same data



```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct chunk_structure{
    size_t prev_size;
    size_t size;
    struct chunk_structure *fd;
    struct chunk_structure *bk;
    char buf[10];
};

int main(){
    unsigned long long *chunk1, *chunk2;
    struct chunk_structure *fake_chunk, *chunk2_hdr;
    char data[20];
    
    chunk1=malloc(0X80);
    chunk2=malloc(0x80);
    printf("%p\n", &chunk1);
    printf("%p\n", chunk1);
    printf("%p\n", chunk2);

    
    fake_chunk = (struct chunk_structure *)chunk1;
    fake_chunk->fd = (struct chunk_structure *)(&chunk1 - 3); 
    fake_chunk->bk = (struct chunk_structure *)(&chunk1 - 2);
    
    chunk2_hdr = (struct chunk_structure *)(chunk2 - 2);
    chunk2_hdr->prev_size=0x80;
    chunk2_hdr->size &=~0x1;
    
    free(chunk2);
    
    chunk1[3] = (unsigned long long)data;
    
    strcpy(data, "Victim's data");
    
    chunk1[0] = 0x002164656b636168LL;
    
    printf("%s\n", data);
       
    return 0;
}
```

#### Altrenative in Rust

As said before raw pointers can be dereferencied only in usafe Rust so modify the pointers is not possible in safe code.

### Double free() Vulnerability

#### Vulnerable C code

This program shows how double freeing "a" the pointers "d" and "f" will point to the same location 

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    char *a = malloc(10*sizeof(char));
    char *b = malloc(10*sizeof(char));
    char *c = malloc(10*sizeof(char));
    
    free(a);
    free(b);
    free(a);
    
    char *d = malloc(10*sizeof(char));
    char *e = malloc(10*sizeof(char));
    char *f = malloc(10*sizeof(char));
    
    char *text = "This is d";
    
    snprintf(d, 10, text);
    
    printf("%s\n", f);
    
    return 0;
}
```

#### Alternative in Rust

Rust after the first drop, as the free() vulnerability example, will not allow to use the dropped varible for the ownership rules.

## Format Strings Vulnerabilities

#### Vulnerable C code

Here if we give to the program some string specifiers as arguments it will print the contents on the stack

```c
#include<stdio.h>
#include<string.h>

int main(int argc, char** argv) {
    char buffer[100];
    strncpy(buffer, argv[1], 100);
    printf(buffer);
    return 0;
}
```
In this other example we can overwrite the memory

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void printstr(char *string){
    for(int i = 3; i>=0; i--){
        printf("%c", string[i]);
    }
    
    printf("\n");
}

void printbuffer(char *string){
    printf(string);
}

void vuln(){
    char buff[512];
    
    fgets(buff, sizeof(buff), stdin);
    
    printbuffer(buff);
    printstr(buff);
    
}

int main(){
    vuln();
    
}
```
The following example give to the program as input four As end ten (number estimated watching the stack in gdb) specifiers in order to see the contents on the stack

![with_A](https://github.com/MarcoArazzi/Secure-C/blob/master/images/with_A.png)

We see that owr four As are on the stack (41414141 ASCII code for AAAA) and we print them. 

![with_A](https://github.com/MarcoArazzi/Secure-C/blob/master/images/with_A2.png)

Now with gdb we verify that the address of the location where the As are stored is the second addres prited so we sobtitute that specifier with an %n in order to modify that location with a number of padding equals to the hexadecimal number of "FOO" (464f4f) in order to overwrite the As with "FOO" 

![with_A](https://github.com/MarcoArazzi/Secure-C/blob/master/images/foo.png)

![with_A](https://github.com/MarcoArazzi/Secure-C/blob/master/images/foo2.png)

#### Alternative in Rust

The first argument of println! is a format string. It is required by the compiler for this to be a string literal; it cannot be a variable passed in (in order to perform validity checking). The compiler will then parse the format string and determine if the list of arguments provided is suitable to pass to this format string.

```rust
use std::io;
use std::io::prelude::*;
use std::io::Write;
use std::str;

fn main() {
    let mut vector = Vec::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines(){
        write!(&mut vector, "{}", &line.unwrap());
        println!("{}",str::from_utf8(&vector).unwrap());
    }
}
```
## Race Condition

####Vulnerable C++ code

Without the lock variable the threads can access the shered data at the same time

```c++
#include <unistd.h>
#include <thread>
#include <iostream>
using namespace std;
int shared_data = 0;
void thread_function(int id) {
    shared_data = id; // start of race window on shared_data
    cout << "Thread " << id << " set shared value to "
         << shared_data << endl;
    usleep(id * 100);
    cout << "Thread " << id << " has shared value as "
         << shared_data << endl;
// end of race window on shared_data
}

int main(void) {
    const size_t thread_size = 10;
    thread threads[thread_size];
    for (size_t i = 0; i < thread_size; i++)
      threads[i] = thread(thread_function, i);
    for (size_t i = 0; i < thread_size; i++)
      threads[i].join();

// Wait until threads are complete before main() continues
    cout << "Done" << endl;
    return 0;
}
```
#### Fixed C++ code

Introducing a lock variabile the race contidion is secure

```c++
#include <unistd.h>
#include <thread>
#include <iostream>
#include <mutex>

using namespace std;

int shared_data = 0;
mutex shared_lock;

void thread_function(int id) {
    shared_lock.lock();
    shared_data = id;
    cout << "Thread " << id << " set shared value to "
         << shared_data << endl;
    usleep(id * 100);
    cout << "Thread " << id << " has shared value as "
         << shared_data << endl;
    shared_lock.unlock();
}

int main(void) {
    const size_t thread_size = 10;
    thread threads[thread_size];
    for (size_t i = 0; i < thread_size; i++)
      threads[i] = thread(thread_function, i);
    for (size_t i = 0; i < thread_size; i++)
      threads[i].join();

// Wait until threads are complete before main() continues
    cout << "Done" << endl;
    return 0;
}
```

#### Alternative in Rust

```rust
use std::sync::{Mutex, Arc};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().unwrap();

            *num += 1;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Result: {}", *counter.lock().unwrap());
}
```

## Polymorphism

### Dynamic Polymorphism

#### Vulnerable C++ code

C extends B that extends A. Both have a function called print that could cause ambiguity when we call it from a C object

```c++
#include <iostream>

using namespace std;

class A {
    public:
        void print()
         {cout<<"A class content\n";}
    public:
        void printA(){
          cout<<"A class content\n";
        }
};

class B : public A {
    public:
        void print()
         {cout<<"B class content\n";}
};

class C : public B{};

int main(){
    C c;
    c.print();
    c.printA();
    return 0;
}
```

#### Alternative in Rust

Rust is not Object Oriented but it is possible to simulate polymorphism with traits

lib.rs:
```rust
pub struct Square{
    
    pub a : u32,
    pub b : u32,
}

pub struct Triangle{
    
    pub a : u32,
    pub b : u32,
}

pub trait Geometry{
    fn area(&self)->u32;
}

impl Geometry for Square{
    fn area(&self)->u32{
        self.a * self.b
    }
}

impl Geometry for Triangle{
    fn area(&self)->u32{
        (self.a * self.b)/2
    }
}
```

main.rs:
```rust
extern crate rust_quite_polymorphism;

use rust_quite_polymorphism::*;
use std::string::String;

fn area_as_string<T:Geometry>(shape:T)->String{
    
    format!("The area of the shape is {}", shape.area())
}

fn main() {
    let sqr = Square{
        a : 2,
        b : 3,
    };
    
    let tri = Triangle{
        a:5,
        b:4,
    };
    
    println!("{}", area_as_string(sqr));
    println!("{}", area_as_string(tri));
}
```




