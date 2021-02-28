use pcap::{Device, Capture, Direction};
use photon_decode::{Photon, Message};

mod photon_messages;

use crate::photon_messages::into_game_message;

fn main() {

    let mut cap = Capture::from_device(Device::lookup().unwrap())
        .unwrap()
        .open()
        .unwrap();

    cap.direction(Direction::In).unwrap();
    cap.filter("port 5056").unwrap();

    let mut photon = Photon::new();
    let photon_packet = vec![
        0x00, 0x01, 			// PeerID
        0x01,                   // CrcEnabled
        0x00,                   // CommandCount
        0x00, 0x00, 0x00, 0x01, // Timestamp
        0x00, 0x00, 0x00, 0x01, // Challenge
    ];


    while let Ok(packet) = cap.next() {

        let mut messages: Vec<Message> = photon
            .decode(packet.data)
            .into_iter()
            .filter_map(into_game_message)
            .collect();


        println!("Received packet {:?} \n Decoded into messages {:?}", packet.data,  messages);
        for message in photon.try_decode(packet.data).into_iter() {
            println!("Hello");
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

}