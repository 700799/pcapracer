//! First-line banner capture for text protocols (SSH/FTP/SMTP/POP3/IMAP).

/// Identify a server (or client) banner and return `(app_proto, banner_line)`.
pub fn parse(buf: &[u8], src_port: u16, dst_port: u16) -> Option<(&'static str, String)> {
    if buf.len() < 3 {
        return None;
    }
    let line = first_line(buf);
    if line.is_empty() {
        return None;
    }

    let proto = if buf.starts_with(b"SSH-") {
        "ssh"
    } else if buf.starts_with(b"+OK") || buf.starts_with(b"-ERR") {
        "pop3"
    } else if buf.starts_with(b"* OK") || buf.starts_with(b"* ") {
        "imap"
    } else if buf.starts_with(b"220") || buf.starts_with(b"421") {
        // 220 service ready — FTP or SMTP; disambiguate by well-known port.
        match port_of(src_port, dst_port, &[21, 20]) {
            true => "ftp",
            false => match port_of(src_port, dst_port, &[25, 587, 465]) {
                true => "smtp",
                false => "ftp",
            },
        }
    } else {
        return None;
    };
    Some((proto, line))
}

fn port_of(sp: u16, dp: u16, ports: &[u16]) -> bool {
    ports.contains(&sp) || ports.contains(&dp)
}

fn first_line(buf: &[u8]) -> String {
    let end = buf
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(buf.len().min(256));
    let slice = &buf[..end.min(256)];
    let mut s = String::with_capacity(slice.len());
    for &b in slice {
        s.push(if (0x20..=0x7e).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_banner() {
        let (p, line) = parse(b"SSH-2.0-OpenSSH_9.0\r\n", 22, 40000).unwrap();
        assert_eq!(p, "ssh");
        assert_eq!(line, "SSH-2.0-OpenSSH_9.0");
    }

    #[test]
    fn ftp_vs_smtp() {
        let (p, _) = parse(b"220 ProFTPD\r\n", 21, 40000).unwrap();
        assert_eq!(p, "ftp");
        let (p, _) = parse(b"220 mail.example.com ESMTP\r\n", 25, 40000).unwrap();
        assert_eq!(p, "smtp");
    }
}
