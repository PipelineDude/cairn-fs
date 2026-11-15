use age::x25519::Identity;
fn main() {
    let id = Identity::generate();
    println!("{}", id.to_public());
}
