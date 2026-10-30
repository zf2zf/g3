/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! Shared control-channel parsing and data-channel helpers used
//! by both the native FTP proxy task and the FTP-over-HTTP-CONNECT
//! bridge. Keeping a single implementation means both paths behave
//! consistently when detecting STOR/STOU/APPE and rewriting
//! PASV/EPSV responses.
//!
//! 控制通道解析与数据通道辅助函数，供原生 FTP 代理任务和
//! FTP-over-HTTP-CONNECT 桥接共用。只保留一份实现，
//! 两条路径在识别 STOR/STOU/APPE、改写 PASV/EPSV 应答时行为一致。

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt};

/// 单行 FTP 命令的最大字节数，超出视为非法输入
const MAX_FTP_LINE: usize = 8192;
/// 单个 FTP 应答（含多行）的最大字节数，超出即截断返回
const MAX_FTP_RESPONSE: usize = 65536;

/// 判断是否为上传类命令：STOR / STOU / APPE（大小写不敏感）。
pub(crate) fn is_upload_command(line: &[u8]) -> bool {
    // 只取行首连续的字母作为命令名，避免匹配到参数中的字符串
    let end = line.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if end == 0 {
        return false;
    }
    let upper = line[..end].to_ascii_uppercase();
    matches!(upper.as_slice(), b"STOR" | b"STOU" | b"APPE")
}

/// 判断是否为被动模式协商命令：PASV 或 EPSV。
pub(crate) fn is_pasv_command(line: &[u8]) -> bool {
    let end = line.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if end == 0 {
        return false;
    }
    let trimmed = &line[..end];
    trimmed.eq_ignore_ascii_case(b"PASV") || trimmed.eq_ignore_ascii_case(b"EPSV")
}

/// 判断是否为 EPSV 命令（应答改写时需要保持 `(|||port|)` 管道格式）。
pub(crate) fn is_epsv_command(line: &[u8]) -> bool {
    let end = line.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if end == 0 {
        return false;
    }
    let trimmed = &line[..end];
    trimmed.eq_ignore_ascii_case(b"EPSV")
}

/// Commands that require an already-opened data channel.
/// Used to determine when to consume a `pending_data` listener
/// and relay traffic between client and server.
/// 需要用到（已由 PASV/EPSV 预留的）数据通道的命令：
/// 上传 STOR/STOU/APPE 与下载 LIST/NLST/RETR。
pub(crate) fn is_data_channel_command(line: &[u8]) -> bool {
    let end = line.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if end == 0 {
        return false;
    }
    let upper = line[..end].to_ascii_uppercase();
    matches!(
        upper.as_slice(),
        b"STOR" | b"STOU" | b"APPE" | b"LIST" | b"NLST" | b"RETR"
    )
}

/// 判断是否为 `AUTH TLS` 命令（显式 FTPS 升级）。
pub(crate) fn is_auth_tls_command(line: &[u8]) -> bool {
    let end = line.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if end == 0 {
        return false;
    }
    let trimmed = &line[..end];
    trimmed.eq_ignore_ascii_case(b"AUTH")
        && line
            .get(end)
            .map(|b| b.is_ascii_whitespace())
            .unwrap_or(false)
        && line[end + 1..].trim_ascii().eq_ignore_ascii_case(b"TLS")
}

/// 按行读取（以 '\n' 结束），累计长度超过 [`MAX_FTP_LINE`] 时返回错误。
/// 直接基于 `BufReader` 的 fill_buf/consume 操作，避免整行拷贝时的额外缓冲。
pub(crate) async fn read_line_limited<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<usize, std::io::Error>
where
    R: AsyncBufRead + Unpin,
{
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // 对端关闭且没有残留数据
            return Ok(total);
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            // 缓冲区里已含行尾，整行取出后返回（含 '\n'）
            let take = pos + 1;
            if total + take > MAX_FTP_LINE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FTP line too long",
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(total + take);
        }
        // 尚无行尾：把当前缓冲全部并入结果，继续等待更多数据
        let avail_len = available.len();
        if total + avail_len > MAX_FTP_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "FTP line too long",
            ));
        }
        buf.extend_from_slice(available);
        reader.consume(avail_len);
        total += avail_len;
    }
}

/// 读取一条完整的 FTP 应答。
/// 按 2048 字节块读，直到攒出一条完整应答（可能是多行）为止，
/// 最多缓冲 [`MAX_FTP_RESPONSE`] 字节；超限时若已有数据则截断返回。
/// 不要求读端是 `BufReader`，因此控制流与隧道流都能直接使用。
/// 读到 EOF / 出错时，若已有数据仍会把已收到的部分返回。
pub(crate) async fn read_ftp_response<R>(ups_r: &mut R) -> Option<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut tmp = [0u8; 2048];
    loop {
        match ups_r.read(&mut tmp).await {
            Ok(0) => {
                return if buf.is_empty() { None } else { Some(buf) };
            }
            Ok(n) => {
                if buf.len() + n > MAX_FTP_RESPONSE {
                    return if buf.is_empty() { None } else { Some(buf) };
                }
                buf.extend_from_slice(&tmp[..n]);
                if is_complete_response(&buf) {
                    return Some(buf);
                }
            }
            Err(_) => {
                return if buf.is_empty() { None } else { Some(buf) };
            }
        }
    }
}

/// 判断缓冲区里是否已凑成一条完整的 FTP 应答。
///
/// 规则：首行为 `NNN ` 即结束；首行为 `NNN-` 表示多行应答，
/// 直到出现同样三位数字后跟空格的结束行为止。
/// 首行不符合规范时按“已完成”处理，避免无限等待。
fn is_complete_response(buf: &[u8]) -> bool {
    let mut i = 0usize;
    // 多行应答时记录需要匹配的结束状态码
    let mut expect_code: Option<[u8; 3]> = None;
    while i < buf.len() {
        if let Some(nl) = buf[i..].iter().position(|b| *b == b'\n') {
            let line_end = i + nl + 1;
            let line = &buf[i..line_end];
            if expect_code.is_none() {
                if line.len() >= 4 && line[..3].iter().all(|b| b.is_ascii_digit()) {
                    let mut code = [0u8; 3];
                    code.copy_from_slice(&line[..3]);
                    if line[3] == b' ' {
                        return true;
                    } else if line[3] == b'-' {
                        expect_code = Some(code);
                    } else {
                        return true;
                    }
                } else {
                    return true;
                }
            } else if let Some(expected) = expect_code
                && line.len() >= 4
                && &line[..3] == expected.as_slice()
                && line[3] == b' '
            {
                return true;
            }
            i = line_end;
        } else {
            // 末行还没有换行符，继续等待更多数据
            break;
        }
    }
    false
}

/// 解析被动模式应答中的上游数据地址。
///
/// 先尝试 EPSV 的 `(|||port|)`，再退回 PASV 的 `(h1,h2,h3,h4,p1,p2)`。
/// `ctrl_peer_ip` 为控制通道对端的 IPv4，供 EPSV 补全地址使用。
pub(crate) fn parse_pasv_response(resp: &[u8], ctrl_peer_ip: Ipv4Addr) -> Option<SocketAddr> {
    // Try EPSV format first: "229 ... (|||port|)"
    if let Some(addr) = parse_epsv_response(resp, ctrl_peer_ip) {
        return Some(addr);
    }
    // Fall back to PASV format: "227 ... (h1,h2,h3,h4,p1,p2)"
    let start = resp.iter().position(|b| *b == b'(')?;
    let end = resp[start..].iter().position(|b| *b == b')')? + start;
    let body = &resp[start + 1..end];
    let parts: Vec<&[u8]> = body.split(|b| *b == b',').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut nums = [0u16; 6];
    for (i, p) in parts.iter().enumerate() {
        let trimmed = trim_ascii(p);
        let s = std::str::from_utf8(trimmed).ok()?;
        nums[i] = s.parse().ok()?;
    }
    // 前 4 段是 IPv4 各字节，后 2 段是端口的高低字节
    let ip = Ipv4Addr::new(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8);
    let port = (nums[4] << 8) | nums[5];
    Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Parse an EPSV response: "229 ... (|||port|)" → (control_ip, port).
/// EPSV returns only the port; the IP is inherited from the control
/// channel TCP 4-tuple, so callers must supply `ctrl_peer_ip`.
/// 解析 EPSV 应答：`229 ... (|||port|)` -> (控制通道对端地址, port)。
/// EPSV 只返回端口号，IP 沿用控制连接的四元组，因此调用方必须传入 `ctrl_peer_ip`。
pub(crate) fn parse_epsv_response(
    resp: &[u8],
    ctrl_peer_ip: std::net::Ipv4Addr,
) -> Option<SocketAddr> {
    // EPSV response must start with "229 " (code 229)
    // EPSV 应答必须以状态码 229 开头
    if resp.len() < 4 || &resp[0..4] != b"229 " {
        return None;
    }
    // Find the opening paren
    // 定位左括号
    let start = resp.iter().position(|b| *b == b'(')?;
    let end = resp[start..].iter().position(|b| *b == b')')? + start;
    let body = &resp[start + 1..end];
    // Format: "|||port|"
    // 形如 "|||port|"
    let body = trim_ascii(body);
    if !body.starts_with(b"|||") || !body.ends_with(b"|") {
        return None;
    }
    let port_str = &body[3..body.len() - 1];
    let port: u16 = std::str::from_utf8(port_str).ok()?.parse().ok()?;
    Some(SocketAddr::V4(SocketAddrV4::new(ctrl_peer_ip, port)))
}

/// 去掉首尾的 ASCII 空白，不改变原缓冲的所有权。
fn trim_ascii(mut data: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = data.split_first() {
        if first.is_ascii_whitespace() {
            data = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = data.split_last() {
        if last.is_ascii_whitespace() {
            data = rest;
        } else {
            break;
        }
    }
    data
}

/// Rewrite a PASV (code 227) response: replace `(h1,h2,h3,h4,p1,p2)`
/// with the local listener's IPv4 address and port.
/// Returns the original bytes unchanged if the response isn't a PASV response
/// or no local address is available.
/// 改写 PASV（状态码 227）应答：把括号中的 `(h1,h2,h3,h4,p1,p2)` 换成本机
/// 数据监听的 IPv4 地址与端口，从而把客户端的数据连接牵引到代理上。
/// 不是 PASV 应答、或拿不到本机监听地址时，原样返回。
pub(crate) fn rewrite_pasv_response(original: &[u8], local_addr: Option<SocketAddr>) -> Vec<u8> {
    // 仅支持 IPv4：监听地址是 IPv6 时不做改写
    let Some(SocketAddr::V4(v4)) = local_addr else {
        return original.to_vec();
    };
    let ip = v4.ip().octets();
    let port = v4.port();
    // 端口拆成高低两字节写回 FTP 的六元组表示
    let p1 = (port >> 8) as u8;
    let p2 = (port & 0xff) as u8;
    let mut new_portion = Vec::with_capacity(32);
    let _ = write!(
        new_portion,
        "({},{},{},{},{},{})",
        ip[0], ip[1], ip[2], ip[3], p1, p2
    );
    let Some(start) = original.iter().position(|b| *b == b'(') else {
        return original.to_vec();
    };
    // Find closing paren after the opening paren
    // 找到左括号之后的右括号
    let Some(end_from_start) = original[start..].iter().position(|b| *b == b')') else {
        return original.to_vec();
    };
    // end points AT the closing paren; we want to skip it
    // end 指向右括号的下一个位置，替换时把右括号一并跳过
    let end = start + end_from_start + 1;
    let mut out = Vec::with_capacity(original.len() + 16);
    out.extend_from_slice(&original[..start]);
    out.extend_from_slice(&new_portion);
    out.extend_from_slice(&original[end..]);
    out
}

/// Rewrite an EPSV (code 229) response: replace the port inside `(|||port|)`
/// with the given port while keeping the pipe-format intact.
/// Returns the original bytes unchanged if the response isn't an EPSV response.
/// 改写 EPSV（状态码 229）应答：只替换 `(|||port|)` 中的端口，保留管道格式
/// （EPSV 的 IP 由客户端从控制通道推断，无需改写）。
/// 不是 EPSV 应答时原样返回。
pub(crate) fn rewrite_epsv_response(original: &[u8], local_port: u16) -> Vec<u8> {
    let Some(start) = original.iter().position(|b| *b == b'(') else {
        return original.to_vec();
    };
    let Some(end_from_start) = original[start..].iter().position(|b| *b == b')') else {
        return original.to_vec();
    };
    let end = start + end_from_start + 1;
    let mut out = Vec::with_capacity(original.len() + 16);
    out.extend_from_slice(&original[..start]);
    let _ = write!(out, "(|||{}|)", local_port);
    out.extend_from_slice(&original[end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // =====================================================================
    // is_upload_command tests
    // =====================================================================
    #[test]
    fn is_upload_command_stor() {
        assert!(is_upload_command(b"STOR file.txt\r\n"));
        assert!(is_upload_command(b"stor file.txt\r\n"));
        assert!(is_upload_command(b"StOr file.txt\r\n"));
    }

    #[test]
    fn is_upload_command_stou() {
        assert!(is_upload_command(b"STOU\r\n"));
        assert!(is_upload_command(b"stou\r\n"));
    }

    #[test]
    fn is_upload_command_appe() {
        assert!(is_upload_command(b"APPE existing.txt\r\n"));
        assert!(is_upload_command(b"appe existing.txt\r\n"));
    }

    #[test]
    fn is_upload_command_not_upload() {
        assert!(!is_upload_command(b"USER ftpuser\r\n"));
        assert!(!is_upload_command(b"PASS ftppass\r\n"));
        assert!(!is_upload_command(b"LIST\r\n"));
        assert!(!is_upload_command(b"RETR file.txt\r\n"));
        assert!(!is_upload_command(b"PASV\r\n"));
        assert!(!is_upload_command(b"CWD /pub\r\n"));
    }

    #[test]
    fn is_upload_command_empty() {
        assert!(!is_upload_command(b"\r\n"));
        assert!(!is_upload_command(b""));
        assert!(!is_upload_command(b"   \r\n"));
    }

    #[test]
    fn is_upload_command_with_trailing_spaces() {
        // leading spaces prevent detection (first char must be alphabetic)
        assert!(!is_upload_command(b"  STOR file.txt\r\n"));
        // spaces after command are fine
        assert!(is_upload_command(b"STOR  file.txt  \r\n"));
    }

    // =====================================================================
    // is_pasv_command tests
    // =====================================================================
    #[test]
    fn is_pasv_command_pasv() {
        assert!(is_pasv_command(b"PASV\r\n"));
        assert!(is_pasv_command(b"pasv\r\n"));
        assert!(is_pasv_command(b"Pasv\r\n"));
    }

    #[test]
    fn is_pasv_command_epsv() {
        assert!(is_pasv_command(b"EPSV\r\n"));
        assert!(is_pasv_command(b"epsv\r\n"));
        assert!(is_pasv_command(b"EPSV 1\r\n"));
    }

    #[test]
    fn is_pasv_command_not_pasv() {
        assert!(!is_pasv_command(b"PORT 192,168,1,1,4,1\r\n"));
        assert!(!is_pasv_command(b"EPRT |2|::1|54321|\r\n"));
        assert!(!is_pasv_command(b"USER ftpuser\r\n"));
        assert!(!is_pasv_command(b"LIST\r\n"));
    }

    #[test]
    fn is_pasv_command_empty() {
        assert!(!is_pasv_command(b"\r\n"));
        assert!(!is_pasv_command(b""));
    }

    // =====================================================================
    // is_complete_response tests
    // =====================================================================
    #[test]
    fn is_complete_response_single_line() {
        assert!(is_complete_response(b"220 FTP Server ready\r\n"));
        assert!(is_complete_response(b"200 Command OK\r\n"));
        assert!(is_complete_response(b"150 Opening data connection\r\n"));
        assert!(is_complete_response(b"226 Transfer complete\r\n"));
        assert!(is_complete_response(b"530 Login authentication failed\r\n"));
    }

    #[test]
    fn is_complete_response_multi_line() {
        assert!(is_complete_response(
            b"220-First line\r\n220 Second line\r\n"
        ));
        assert!(is_complete_response(
            b"220-Line1\r\n220-Line2\r\n220 Final line\r\n"
        ));
        assert!(is_complete_response(
            b"230-User logged in\r\n230-\r\n230 Welcome\r\n"
        ));
    }

    #[test]
    fn is_complete_response_incomplete() {
        assert!(!is_complete_response(b"220"));
        assert!(!is_complete_response(b"220-"));
        assert!(!is_complete_response(b"220 First line"));
        assert!(!is_complete_response(b"220-First line"));
        assert!(!is_complete_response(b""));
    }

    #[test]
    fn is_complete_response_invalid_first_line() {
        assert!(is_complete_response(b"Not a code\r\n")); // invalid first line => complete
        assert!(is_complete_response(b"abc\r\n"));
    }

    #[test]
    fn is_complete_response_mixed_lines() {
        // 123 bad first line => returns true (deemed complete)
        assert!(is_complete_response(b"123\r\n"));
        // 220 followed by continuation then final line with matching code + space
        assert!(is_complete_response(b"220-FTP server\r\n220 OK\r\n"));
        // 220 continuation followed by different code => incomplete (expected 220, got 221)
        assert!(!is_complete_response(
            b"220-FTP server\r\n221 Different\r\n"
        ));
    }

    // =====================================================================
    // parse_pasv_response tests (also covers EPSV via passthrough)
    // =====================================================================
    #[test]
    fn parse_pasv_response_basic() {
        // 227 Entering Passive Mode (192,168,1,1,4,1) => port = 4*256+1 = 1025
        let resp = b"227 Entering Passive Mode (192,168,1,1,4,1)\r\n";
        let addr = parse_pasv_response(resp, Ipv4Addr::new(10, 0, 0, 1));
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.ip().to_string(), "192.168.1.1");
        assert_eq!(addr.port(), 1025);
    }

    #[test]
    fn parse_pasv_response_with_spaces() {
        let resp = b"227 Entering Passive Mode ( 192 , 168 , 1 , 1 , 4 , 1 )\r\n";
        let addr = parse_pasv_response(resp, Ipv4Addr::LOCALHOST);
        assert!(addr.is_some());
        assert_eq!(addr.unwrap().port(), 1025);
    }

    #[test]
    fn parse_pasv_response_high_port() {
        // port = 255*256+255 = 65535
        let resp = b"227 (192,168,1,1,255,255)\r\n";
        let addr = parse_pasv_response(resp, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(addr.port(), 65535);
    }

    #[test]
    fn parse_pasv_response_low_port() {
        // port = 0*256+20 = 20
        let resp = b"227 (10,0,0,1,0,20)\r\n";
        let addr = parse_pasv_response(resp, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(addr.port(), 20);
    }

    #[test]
    fn parse_pasv_response_invalid() {
        assert!(parse_pasv_response(b"220 OK\r\n", Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_pasv_response(b"227 no parens\r\n", Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_pasv_response(b"227 (1,2,3)\r\n", Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_pasv_response(b"227 (a,b,c,d,e,f)\r\n", Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_pasv_response(b"", Ipv4Addr::LOCALHOST).is_none());
        assert!(parse_pasv_response(b"227 ()\r\n", Ipv4Addr::LOCALHOST).is_none());
    }

    // =====================================================================
    // EPSV parsing tests
    // =====================================================================
    #[test]
    fn parse_epsv_response_basic() {
        // 229 Entering Extended Passive Mode (|||12345|) => port = 12345
        let resp = b"229 Entering Extended Passive Mode (|||12345|)\r\n";
        let ctrl_ip = Ipv4Addr::new(192, 168, 1, 100);
        let addr = parse_epsv_response(resp, ctrl_ip);
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 12345);
        let IpAddr::V4(addr_ip) = addr.ip() else {
            panic!("expected IPv4")
        };
        assert_eq!(addr_ip, ctrl_ip);
    }

    #[test]
    fn parse_epsv_response_low_port() {
        let resp = b"229 EPSV (|||21|)\r\n";
        let ctrl_ip = Ipv4Addr::new(10, 0, 0, 1);
        let addr = parse_epsv_response(resp, ctrl_ip).unwrap();
        assert_eq!(addr.port(), 21);
    }

    #[test]
    fn parse_epsv_response_high_port() {
        let resp = b"229 (|||65535|)\r\n";
        let addr = parse_epsv_response(resp, Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(addr.port(), 65535);
    }

    #[test]
    fn parse_epsv_response_invalid() {
        // Wrong code
        assert!(parse_epsv_response(b"227 (|||12345|)\r\n", Ipv4Addr::LOCALHOST).is_none());
        // Missing pipes
        assert!(parse_epsv_response(b"229 (|12345|)\r\n", Ipv4Addr::LOCALHOST).is_none());
        // Empty port
        assert!(parse_epsv_response(b"229 (||||)\r\n", Ipv4Addr::LOCALHOST).is_none());
        // Non-numeric port
        assert!(parse_epsv_response(b"229 (|||abc|)\r\n", Ipv4Addr::LOCALHOST).is_none());
    }

    // Verify parse_pasv_response dispatches to EPSV format correctly
    #[test]
    fn parse_pasv_response_epsv_dispatch() {
        // 229 EPSV response should be resolved using the control peer IP
        let resp = b"229 Entering Extended Passive Mode (|||54321|)\r\n";
        let ctrl_ip = Ipv4Addr::new(203, 0, 113, 10);
        let addr = parse_pasv_response(resp, ctrl_ip);
        assert!(addr.is_some());
        let addr = addr.unwrap();
        assert_eq!(addr.port(), 54321);
        let IpAddr::V4(addr_ip) = addr.ip() else {
            panic!("expected IPv4")
        };
        assert_eq!(addr_ip, ctrl_ip);
    }

    // =====================================================================
    // rewrite_pasv_response tests
    // =====================================================================
    #[test]
    fn rewrite_pasv_response_basic() {
        let resp = b"227 Entering Passive Mode (192,168,1,1,4,1)\r\n";
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let rewritten = rewrite_pasv_response(resp, Some(local));
        // 5000 = (19, 136): 19*256+136=5000
        let expected = b"(127,0,0,1,19,136)";
        assert!(rewritten.windows(expected.len()).any(|w| w == expected));
        // Should not contain original address bytes
        assert!(!rewritten.windows(4).any(|w| w == b"192."));
    }

    #[test]
    fn rewrite_pasv_response_v6_ignored() {
        // IPv6 address should cause passthrough
        let resp = b"227 (192,168,1,1,4,1)\r\n";
        let local: SocketAddr = "[::1]:21".parse().unwrap();
        let rewritten = rewrite_pasv_response(resp, Some(local));
        assert_eq!(rewritten, resp);
    }

    #[test]
    fn rewrite_pasv_response_no_local_addr() {
        let resp = b"227 (192,168,1,1,4,1)\r\n";
        let rewritten = rewrite_pasv_response(resp, None);
        assert_eq!(rewritten, resp);
    }

    #[test]
    fn rewrite_pasv_response_missing_parens() {
        let resp = b"227 no parens here\r\n";
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(rewrite_pasv_response(resp, Some(local)), resp);
    }

    #[test]
    fn rewrite_pasv_response_preserves_surrounding() {
        // Preserve text before '(' and after ')'
        let resp = b"220-227 text before (192,168,1,1,4,1) text after\r\n";
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let rewritten = rewrite_pasv_response(resp, Some(local));
        assert!(rewritten.starts_with(b"220-227 text before "));
        assert!(rewritten.ends_with(b" text after\r\n"));
    }

    #[test]
    fn rewrite_pasv_response_no_double_paren() {
        // Ensure no '))' appears in output
        let resp = b"227 Entering Passive Mode (192,168,1,1,4,1)\r\n";
        let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let rewritten = rewrite_pasv_response(resp, Some(local));
        // Count closing parens - should be exactly one
        let close_count = rewritten.iter().filter(|b| **b == b')').count();
        assert_eq!(
            close_count,
            1,
            "output: {:?}",
            String::from_utf8_lossy(&rewritten)
        );
    }

    // =====================================================================
    // is_epsv_command tests
    // =====================================================================
    #[test]
    fn is_epsv_command_basic() {
        assert!(is_epsv_command(b"EPSV\r\n"));
        assert!(is_epsv_command(b"epsv\r\n"));
        assert!(is_epsv_command(b"EPSV 1\r\n"));
        assert!(is_epsv_command(b"EPSV\n"));
    }

    #[test]
    fn is_epsv_command_not_epsv() {
        assert!(!is_epsv_command(b"PASV\r\n"));
        assert!(!is_epsv_command(b"pasv\r\n"));
        assert!(!is_epsv_command(b"STOR\r\n"));
        assert!(!is_epsv_command(b"LIST\r\n"));
    }

    // =====================================================================
    // is_data_channel_command tests
    // =====================================================================
    #[test]
    fn is_data_channel_command_uploads() {
        assert!(is_data_channel_command(b"STOR file.txt\r\n"));
        assert!(is_data_channel_command(b"stou\r\n"));
        assert!(is_data_channel_command(b"APPE existing.txt\r\n"));
    }

    #[test]
    fn is_data_channel_command_downloads() {
        assert!(is_data_channel_command(b"LIST\r\n"));
        assert!(is_data_channel_command(b"LIST /pub\r\n"));
        assert!(is_data_channel_command(b"NLST\r\n"));
        assert!(is_data_channel_command(b"RETR file.txt\r\n"));
    }

    #[test]
    fn is_data_channel_command_not_data() {
        assert!(!is_data_channel_command(b"USER ftpuser\r\n"));
        assert!(!is_data_channel_command(b"PASS secret\r\n"));
        assert!(!is_data_channel_command(b"PASV\r\n"));
        assert!(!is_data_channel_command(b"EPSV\r\n"));
        assert!(!is_data_channel_command(b"QUIT\r\n"));
        assert!(!is_data_channel_command(b""));
    }

    // =====================================================================
    // rewrite_epsv_response tests
    // =====================================================================
    #[test]
    fn rewrite_epsv_response_basic() {
        let resp = b"229 Entering Extended Passive Mode (|||54321|)\r\n";
        let rewritten = rewrite_epsv_response(resp, 12345);
        assert!(rewritten.starts_with(b"229 Entering Extended Passive Mode "));
        assert!(rewritten.ends_with(b"\r\n"));
        let expected = b"(|||12345|)";
        assert!(rewritten.windows(expected.len()).any(|w| w == expected));
        // Should NOT contain the old port
        assert!(!rewritten.windows(5).any(|w| w == b"54321"));
    }

    #[test]
    fn rewrite_epsv_response_no_double_paren() {
        let resp = b"229 Entering Extended Passive Mode (|||54321|)\r\n";
        let rewritten = rewrite_epsv_response(resp, 12345);
        let close_count = rewritten.iter().filter(|b| **b == b')').count();
        assert_eq!(
            close_count,
            1,
            "output: {:?}",
            String::from_utf8_lossy(&rewritten)
        );
    }

    #[test]
    fn rewrite_epsv_response_preserves_code() {
        let resp = b"229 (|||1000|)\r\n";
        let rewritten = rewrite_epsv_response(resp, 2000);
        assert!(rewritten.starts_with(b"229 "));
        assert!(rewritten.ends_with(b"\r\n"));
    }

    #[test]
    fn rewrite_epsv_response_missing_parens() {
        let resp = b"229 no parens here\r\n";
        assert_eq!(rewrite_epsv_response(resp, 2000), resp);
    }
}
