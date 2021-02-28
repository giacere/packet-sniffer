use pcap::{Device, Capture, Direction};
use photon_decode::{Photon, Message};


fn main() {

    let mut cap = Capture::from_device(Device::lookup().unwrap())
        .unwrap()
        .open()
        .unwrap();

    cap.direction(Direction::In).unwrap();
    cap.filter("portrange 5055-5056").unwrap();

    let mut photon = Photon::new();
    let photon_packet = vec![
    0x00, 0x01, 			// PeerID
    0x01,                   // CrcEnabled
    0x00,                   // CommandCount
    0x00, 0x00, 0x00, 0x01, // Timestamp
    0x00, 0x00, 0x00, 0x01, // Challenge
];

for message in photon.decode(&photon_packet).iter() {
    match message {
        Message::Event(_) => {
            // use event
            println!("Received event: {:?}", message);
        },
        Message::Request(_) => {
            // use request
            println!("Received request: {:?}", message);
        },
        Message::Response(_) => {
            // use response
            println!("Received Response: {:?}", message);
        }
    }
}


    }
