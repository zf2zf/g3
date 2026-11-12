/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP control-channel parsing primitives: command detection and response reading.
//!
//! FTP 控制通道解析原语：命令识别与应答读取。

use tokio::io::{AsyncRead, AsyncReadExt};

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

/// 拆出上传命令的命令名与完整目标路径。
///
/// 参数必须取命令动词之后的整行余部：FTP 文件名允许含空格，按空白切分会把
/// `STOR my report.pdf` 截成 `my`，审计记录里的文件名就是错的。
/// 文件名也允许非 UTF-8 字节（如 GBK 客户端），故走 lossy 转换，
/// 直接按 UTF-8 解析失败会让路径变成空串、审计记录里就没有文件了。
pub(crate) fn parse_upload_command(line: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim_end_matches(['\r', '\n']);
    let end = trimmed
        .bytes()
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    let cmd_name = trimmed[..end].to_ascii_uppercase();
    let ftp_path = trimmed[end..].trim_start().to_string();
    (cmd_name, ftp_path)
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

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // is_upload_command tests
    // =====================================================================
    #[test]
    fn is_upload_command_stor() {
        assert!(is_upload_command(b"STOR file.txt\r\n"));
        assert!(is_upload_command(b"stor file.txt\r\n"));
        assert!(is_upload_command(b"StOr file.txt\r\n"));
    }

    // =====================================================================
    // parse_upload_command tests
    // =====================================================================
    #[test]
    fn parse_upload_command_keeps_spaces_in_path() {
        assert_eq!(
            parse_upload_command(b"STOR my report 2026.pdf\r\n"),
            ("STOR".to_string(), "my report 2026.pdf".to_string())
        );
    }

    #[test]
    fn parse_upload_command_uppercases_verb() {
        assert_eq!(
            parse_upload_command("appe 中文目录/数据.txt\r\n".as_bytes()),
            ("APPE".to_string(), "中文目录/数据.txt".to_string())
        );
    }

    #[test]
    fn parse_upload_command_without_argument() {
        assert_eq!(
            parse_upload_command(b"STOU\r\n"),
            ("STOU".to_string(), String::new())
        );
    }

    #[test]
    fn parse_upload_command_survives_non_utf8_path() {
        // GBK 编码的"报告.txt"：按 UTF-8 硬解会整行失败，lossy 后仍保留文件与扩展名
        let line = b"STOR \xB1\xA8\xB8\xE6.txt\r\n";
        let (cmd, path) = parse_upload_command(line);
        assert_eq!(cmd, "STOR");
        assert!(path.ends_with(".txt"), "{path}");
        assert!(!path.is_empty(), "{path}");
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
}
