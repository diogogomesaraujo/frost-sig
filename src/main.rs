mod lib;

fn main() {
    let pol: Vec<u32> = vec![2, 2];
    let x: u64 = 0;

    let y = lib::calculate_y(x, &pol);

    println!("The value is {y}");
}
