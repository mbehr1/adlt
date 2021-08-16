fn main() {
    println!(
        "I'm using the library: {} v{:?}",
        adlt::name(),
        adlt::version()
    );
    let mut msg1 = adlt::DltMessage::for_test();
    let alc = adlt::lifecycle::Lifecycle::new(&mut msg1);
    println!("Having a: {:?}", alc);
    println!("Having a: {:?}", msg1);
}
