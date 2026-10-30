//! An emulated card behind `vpcd`, the virtual reader of vsmartcard for pcsc-lite: the
//! card connects to the reader's TCP port and answers its frames, so the real PC/SC
//! backend can be tested against it.

use super::SoftCard;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};

/// vpcd's default port.
pub const VPCD_PORT: u16 = 35963;

/// Serves `card` to the vpcd at `addr` until vpcd closes the connection. Frames are
/// `len_be16 ‖ payload`; a one-byte payload is a control code (`00` power off, `01` power
/// on, `02` reset, `04` ATR request, answered with the ATR), anything else a command APDU,
/// answered with the card's response.
///
/// # Errors
///
/// When the connection fails.
pub fn serve_vpcd(mut card: Box<dyn SoftCard>, addr: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    loop {
        let mut len = [0; 2];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let mut payload = vec![0; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut payload)?;
        let answer = match payload.as_slice() {
            [0x00 | 0x02] => {
                card.reset();
                continue;
            }
            [0x04] => card.atr(),
            [_] => continue,
            apdu => card.process(apdu),
        };
        let len = u16::try_from(answer.len())
            .map_err(|_| io::Error::other("a response over 65535 bytes"))?;
        stream.write_all(&[&len.to_be_bytes()[..], &answer].concat())?;
    }
}
