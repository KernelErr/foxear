#[derive(Debug)]
pub enum EventEnum {
    Exec(super::execsnoop::Event),
    Open(super::opensnoop::Event),
    ConnectV4(super::tcpconnect::V4Event),
    ConnectV6(super::tcpconnect::V6Event),
}
