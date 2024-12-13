// move1.rs
fn main() {
    let s1 = "hello dolly".to_string();
    let s2 = s1;
    println!("s1 {}", s1);
}
fn dump(s: &String) {
    println!("{}", s);
}

fn main() {
    let s1 = "hello dolly".to_string();
    dump(&s1);
    println!("s1 {}", s1);
}
dump(&"hello world".to_string());
fn dump(s: &str) {
    println!("{}", s);
}
{
    let a = 10;
    let b = "hello";
    {
        let c = "hello".to_string();
        // a,b and c are visible
    }
    // the string c is dropped
    // a,b are visible
    for i in 0..a {
        let b = &b[1..];
        // original b is no longer visible - it is shadowed.
    }
    // the slice b is dropped
    // i is _not_ visible!
}
// ref1.rs
02 fn main() {
    03    let s1 = "hello dolly".to_string();
    04    let mut rs1 = &s1;
    05    {
    06        let tmp = "hello world".to_string();
    07        rs1 = &tmp;
    08    }
    09    println!("ref {}", rs1);
    10 }

    / tuple1.rs

fn add_mul(x: f64, y: f64) -> (f64,f64) {
    (x + y, x * y)
}

fn main() {
    let t = add_mul(2.0,10.0);

    // can debug print
    println!("t {:?}", t);

    // can 'index' the values
    println!("add {} mul {}", t.0,t.1);

    // can _extract_ values
    let (add,mul) = t;
    println!("add {} mul {}", add,mul);
}
// t (12, 20)
// add 12 mul 20
// add 12 mul 20