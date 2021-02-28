use pcap::{Device, Capture, Direction};
use std::str;

fn main() {

    let mut cap = Capture::from_device(Device::lookup().unwrap())
        .unwrap()
        .open()
        .unwrap();

    cap.direction(Direction::In).unwrap();
    cap.filter("portrange 5055-5056").unwrap();

    while let Ok(packet) = cap.next() {
        let s = match str::from_utf8(packet.data) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        println!("result: {}", s);
    }
}