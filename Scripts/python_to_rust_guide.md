# Python to Rust Guide: Learning from a Real-World Encryption Tool

This guide explains key Rust concepts for Python programmers, using our secure file encryption/decryption tool as an example. We'll explore the major differences between the languages and how to think the "Rust way" coming from Python.

## Table of Contents

1. [Basic Language Differences](#basic-language-differences)
2. [Memory Model and Ownership](#memory-model-and-ownership)
3. [Error Handling](#error-handling)
4. [Type System](#type-system)
5. [Functional Concepts](#functional-concepts)
6. [Modules and Imports](#modules-and-imports)
7. [Collections and Data Structures](#collections-and-data-structures)
8. [Pattern Matching](#pattern-matching)

## Basic Language Differences

### Syntax

| Python | Rust | Notes |
|--------|------|-------|
| `def function_name():` | `fn function_name() {` | Rust uses curly braces for blocks |
| `class MyClass:` | `struct MyStruct {}` and `impl MyStruct {}` | Rust separates data from methods |
| `x = 5` | `let x = 5;` | Rust requires semicolons and variable declarations |
| `x = "string"` | `let x: String = "string".to_string();` | Rust is statically typed |
| `if x == 5:` | `if x == 5 {` | No parentheses required around conditions |
| `for i in range(5):` | `for i in 0..5 {` | Range syntax is different |
| `# Comment` | `// Comment` | Different comment style |
| `"""Docstring"""` | `/// Documentation comment` | Doc comments generate documentation |

### Variables and Mutability

In Python, variables are always mutable by default:

```python
x = 5
x = 10  # Works fine
```

In Rust, variables are immutable by default, and you must declare when you want mutability:

```rust
let x = 5;
x = 10;  // Error: cannot assign twice to immutable variable
let mut y = 5;
y = 10;  // Works fine
```

From our code:

```rust
let mut derived_key = [0u8; 32];  // Mutable variable
let argon2 = Argon2::default();   // Immutable variable
```

## Memory Model and Ownership

This is the biggest difference between Python and Rust. In Python, memory management is handled by the garbage collector, and you rarely think about it:

```python
def process_data(data):
    # Just use data, garbage collector handles memory
    return data.upper()

my_data = "hello"
process_data(my_data)
print(my_data)  # Still available
```

In Rust, the ownership system ensures memory safety without a garbage collector:

```rust
fn process_data(data: String) -> String {
    // This function takes ownership of data
    data.to_uppercase()  // Returns ownership of the new string
}

let my_data = String::from("hello");
let processed = process_data(my_data);
// println!("{}", my_data);  // Error: my_data has been moved
```

To keep using the original data, you'd use references:

```rust
fn process_data(data: &String) -> String {
    // This function borrows data
    data.to_uppercase()
}

let my_data = String::from("hello");
let processed = process_data(&my_data);
println!("{}", my_data);  // Works fine, we only borrowed my_data
```

From our encryption code:

```rust
fn encrypt(data: &[u8], password: &str) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // We borrow data and password (don't take ownership)
    // But we return new owned vectors
}
```

## Error Handling

Python uses exceptions for error handling:

```python
try:
    file = open("file.txt")
    content = file.read()
except FileNotFoundError:
    print("File not found")
```

Rust uses the `Result` type for functions that can fail:

```rust
let file_result = File::open("file.txt");
match file_result {
    Ok(mut file) => {
        let mut content = String::new();
        file.read_to_string(&mut content)?;
    },
    Err(e) => println!("File not found: {}", e),
}
```

The `?` operator in Rust is a shorthand for error propagation. It's like a try/except that returns the error:

```rust
fn read_file() -> io::Result<String> {
    let mut file = File::open("file.txt")?;  // Returns error if this fails
    let mut content = String::new();
    file.read_to_string(&mut content)?;  // Returns error if this fails
    Ok(content)  // Return the content wrapped in Ok
}
```

From our decryption code:

```rust
let (ciphertext, nonce, salt) = read_encrypted_file(&input_path)?;
let password = Password::new()
    .with_prompt("Enter decryption password")
    .interact()?;
```

## Type System

Python uses dynamic typing, where variables can change type at runtime:

```python
x = 5       # x is an int
x = "hello" # Now x is a string
```

Rust uses static typing with type inference:

```rust
let x = 5;        // x is i32 (inferred)
let y: u32 = 5;   // y is u32 (explicit)
// x = "hello";   // Error: cannot change type
```

Rust's type system is much more expressive, with features like:

1. **Enums with data (sum types)**:

```rust
enum Result<T, E> {
    Ok(T),
    Err(E),
}

let result: Result<i32, String> = Ok(5);
```

2. **Traits (similar to interfaces)**:

```rust
trait Readable {
    fn read(&self) -> String;
}

impl Readable for File {
    fn read(&self) -> String {
        // Implementation
    }
}
```

3. **Option type (instead of null/None)**:

```rust
// Python:
def find_user(id):
    if user_exists(id):
        return User(id)
    else:
        return None

# Rust:
fn find_user(id: UserId) -> Option<User> {
    if user_exists(id) {
        Some(User::new(id))
    } else {
        None
    }
}
```

From our code:

```rust
fn check_for_identifier(encrypted_file_path: &Path) -> Option<String> {
    // Returns either Some(identifier) or None
}
```

## Functional Concepts

Rust embraces functional programming concepts more than Python:

**Closures** (anonymous functions):

```python
# Python
numbers = [1, 2, 3, 4]
doubled = list(map(lambda x: x * 2, numbers))
```

```rust
// Rust
let numbers = vec![1, 2, 3, 4];
let doubled: Vec<i32> = numbers.iter().map(|x| x * 2).collect();
```

**Method chaining**:

```rust
// From our code:
let swap_encrypted = Command::new("swapon")
    .arg("--show")
    .output()
    .map(|o| {
        let output = String::from_utf8_lossy(&o.stdout);
        output.contains("crypt") || output.is_empty()
    })
    .unwrap_or(false);
```

## Modules and Imports

Python's import system:

```python
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
```

Rust's module system:

```rust
use std::fs;
use std::path::{Path, PathBuf};
use crypto::digest::Digest;
```

**External dependencies**:

Python uses pip and requirements.txt or pyproject.toml:

```
# requirements.txt
cryptography==3.4.0
```

Rust uses Cargo and Cargo.toml:

```toml
# Cargo.toml
[dependencies]
aes-gcm = "0.10.1"
argon2 = "0.5.0"
```

## Collections and Data Structures

Common collection types:

| Python | Rust | Notes |
|--------|------|-------|
| `list` | `Vec<T>` | Dynamic array |
| `tuple` | `(T1, T2, ...)` | Fixed-size tuple |
| `dict` | `HashMap<K, V>` | Hash map |
| `set` | `HashSet<T>` | Hash set |
| `str` | `String` or `&str` | Owned or borrowed string |
| `bytes` | `Vec<u8>` or `&[u8]` | Byte arrays |

From our code:

```rust
// Fixed-size array with 32 zeros
let mut derived_key = [0u8; 32]; 

// Create a dynamic vector (like Python's list)
let mut compressed_data = Vec::new();  

// Tuple of three elements (like Python's tuple)
let (ciphertext, nonce, salt) = read_encrypted_file(&input_path)?;
```

## Pattern Matching

Rust's `match` expression is much more powerful than Python's `if/elif/else`:

```rust
// Match on Option type
match some_option {
    Some(value) => println!("Got a value: {}", value),
    None => println!("Got nothing"),
}

// Match on Result type
match some_result {
    Ok(success) => println!("Success: {}", success),
    Err(error) => println!("Error: {}", error),
}

// Match on enum
match color {
    Color::Red => println!("It's red!"),
    Color::Green => println!("It's green!"),
    Color::Blue => println!("It's blue!"),
    _ => println!("It's something else"),
}
```

From our code:

```rust
match argon2.hash_password_into(
    password.as_bytes(),
    salt,
    &mut derived_key,
) {
    Ok(_) => {
        // Encryption succeeded
        // ... code here
        Ok((ciphertext, nonce_bytes.to_vec(), salt.as_ref().to_vec()))
    },
    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
}
```

## Summary of Key Differences

1. **Memory Management**: Python uses garbage collection; Rust uses ownership and borrowing
2. **Type System**: Python is dynamically typed; Rust is statically typed
3. **Error Handling**: Python uses exceptions; Rust uses Result and Option types
4. **Mutability**: Python variables are mutable by default; Rust variables are immutable by default
5. **Concurrency**: Python has the GIL; Rust guarantees thread safety via the type system
6. **Performance**: Rust is generally much faster and has lower memory usage
7. **Compilation**: Python is interpreted; Rust is compiled
8. **Ecosystem**: Python has a larger ecosystem for data science and web; Rust is growing but still smaller

## Learning Resources

1. [The Rust Book](https://doc.rust-lang.org/book/)
2. [Rust By Example](https://doc.rust-lang.org/rust-by-example/)
3. [Rustlings](https://github.com/rust-lang/rustlings) - Small exercises to learn Rust
4. [Exercism Rust Track](https://exercism.io/tracks/rust)
5. [The Cargo Book](https://doc.rust-lang.org/cargo/)

Remember, learning Rust from Python involves a significant paradigm shift, especially around memory management and the ownership system. Be patient with yourself, and focus on understanding these core concepts before diving too deep into advanced features. 