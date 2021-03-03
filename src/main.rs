use pcap::{Device, Capture, Direction};
use photon_decode::*;
use std::process::exit;

fn main() {

    let mut cap = Capture::from_device(Device::lookup().unwrap())
        .unwrap()
        .open()
        .unwrap();

    cap.direction(Direction::In).unwrap();
    cap.filter("port 5056").unwrap();

    let mut payload: &[u8] = &[96, 69, 203, 157, 167, 73, 64, 93, 130, 254, 39, 68, 8, 0, 69, 0, 0, 200, 120, 237, 0, 0, 114, 17, 139, 161, 5, 188, 125, 44, 192, 168, 0, 6, 19, 192, 173, 149, 0, 180, 52, 209, 0, 0, 0, 1, 1, 130, 53, 51, 54, 130, 161, 245, 6, 0, 1, 0, 0, 0, 0, 160, 0, 0, 9, 225, 243, 4, 1, 0, 19, 0, 105, 0, 13, 109, 20, 1, 107, 8, 81, 2, 107, 27, 45, 3, 121, 0, 2, 102, 192, 179, 244, 99, 66, 202, 86, 110, 4, 102, 66, 62, 42, 214, 5, 120, 0, 0, 0, 16, 146, 65, 130, 209, 34, 218, 38, 65, 147, 80, 60, 205, 201, 85, 53, 204, 6, 98, 0, 7, 98, 3, 8, 107, 55, 44, 9, 120, 0, 0, 0, 16, 142, 165, 85, 16, 95, 208, 70, 74, 184, 34, 255, 254, 248, 20, 238, 109, 10, 120, 0, 0, 0, 16, 97, 57, 134, 204, 28, 108, 255, 66, 189, 21, 178, 132, 207, 61, 114, 245, 11, 98, 7, 12, 98, 2, 13, 98, 12, 14, 98, 51, 15, 105, 0, 255, 255, 255, 16, 102, 189, 76, 204, 205, 17, 102, 63, 140, 204, 205, 252, 107, 1, 33];
            payload =        &[96, 69, 203, 157, 167, 73, 64, 93, 130, 254, 39, 68, 8, 0, 69, 0, 0, 60, 111, 44, 0, 0, 114, 17, 149, 238, 5, 188, 125, 44, 192, 168, 0, 6, 19, 192, 173, 149, 0, 40, 228, 187, 0, 0, 0, 1, 1, 114, 38, 233, 54, 130, 161, 245, 1, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 89, 0, 17, 19, 164];
    let mut photon = Photon::new();
    for message in photon.try_decode(payload).iter() {
        //println!("Decoded message: {:?}", message);
        exit(0)
    }

    while let Ok(packet) = cap.next() {

        println!("Received packet header {:?} \n ", packet.header);
        println!("Received packet data {:?} \n ", packet.data);

        for message in photon.try_decode(packet.data).iter() {
            println!("Decoded message: {:?}", message);
            exit(0)
        }
    }

}
