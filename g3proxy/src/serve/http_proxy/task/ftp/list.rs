/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::io::{self, Write};

use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};

use g3_ftp_client::FtpLineDataReceiver;
use g3_io_ext::LimitedWriteExt;

// chunked 编码缓冲区头部（十六进制长度行 \r\n）与尾部（\r\n）预留的字节数
const CHUNKED_BUF_HEAD_RESERVED: usize = (usize::BITS as usize >> 2) + 2;
const CHUNKED_BUF_TAIL_RESERVED: usize = 2;

/// FTP 目录列表写出器抽象：在 g3-ftp-client 逐行回调（FtpLineDataReceiver）的基础上，
/// 增加 IO 错误暂存、缓冲刷新与空闲状态查询，供任务主循环做 idle 检测。
pub(super) trait ListWriter: FtpLineDataReceiver {
    /// 取出收集期间暂存的写客户端错误（如有）
    fn take_io_error(&mut self) -> Option<io::Error>;
    /// 把剩余缓冲数据刷到客户端，并结束 body（chunked 结束块或普通 flush）
    async fn flush_buf(&mut self) -> io::Result<()>;
    /// 自上次 reset_active 以来是否未收到任何列表数据行
    #[allow(unused)]
    fn is_idle(&self) -> bool;
    /// 清除活跃标记，重新开始空闲统计
    #[allow(unused)]
    fn reset_active(&mut self);
    /// 缓冲区内是否没有未发出的数据
    #[allow(unused)]
    fn no_cached_data(&self) -> bool;
}

/// HTTP chunked 编码的列表写出器：按行累积到内部缓冲区，凑满后补上 chunk 长度头再发出。
///
/// 缓冲区开头预留了头部空间，发送时把长度行右对齐写入预留区，避免额外拷贝。
pub(super) struct ChunkedListWriter<'a, W> {
    buf_len: usize,              // 当前已写入的字节数（含预留头部）
    buf_cap: usize,              // 可容纳列表数据的上限
    buf: Vec<u8>,                // 数据缓冲（[预留头部][列表数据...]）
    writer: &'a mut W,           // 客户端 HTTP 输出流
    io_error: Option<io::Error>, // 写出失败时暂存的错误
    active: bool,                // 是否收到过数据行（空闲检测用）
}

impl<'a, W> ChunkedListWriter<'a, W>
where
    W: AsyncWrite + Unpin,
{
    /// 创建写出器；buf_size 为纯数据区大小，实际分配会加上头尾预留
    pub(super) fn new(writer: &'a mut W, buf_size: usize) -> Self {
        let mut buf =
            Vec::with_capacity(CHUNKED_BUF_HEAD_RESERVED + buf_size + CHUNKED_BUF_TAIL_RESERVED);
        buf.extend_from_slice(&[0u8; CHUNKED_BUF_HEAD_RESERVED]);
        ChunkedListWriter {
            buf_len: CHUNKED_BUF_HEAD_RESERVED,
            buf_cap: buf_size + CHUNKED_BUF_HEAD_RESERVED,
            buf,
            writer,
            io_error: None,
            active: false,
        }
    }

    /// 将当前缓冲作为一个 chunk 发出：生成 "<hex-len>\r\n" 长度行（右对齐嵌入预留头部），
    /// 追加 chunk 尾 "\r\n"，然后整体写出并重置缓冲
    async fn send_buf(&mut self) -> io::Result<()> {
        let chunked_header = format!("{:x}\r\n", self.buf_len - CHUNKED_BUF_HEAD_RESERVED);
        let offset = CHUNKED_BUF_HEAD_RESERVED - chunked_header.len();
        let mut head = &mut self.buf[offset..];
        let _ = head.write_all(chunked_header.as_bytes());
        self.buf.extend_from_slice(b"\r\n");
        self.writer.write_all(&self.buf[offset..]).await?;

        self.buf_cap = self.buf.capacity() - CHUNKED_BUF_TAIL_RESERVED;
        self.buf_len = CHUNKED_BUF_HEAD_RESERVED;
        self.buf.truncate(self.buf_len);
        Ok(())
    }
}

/// 逐行接收 FTP 客户端库回调传来的列表数据行；缓冲不足时先发出已有 chunk。
/// 写错误只暂存不抛出，由 should_return_early 让上层尽快退出接收循环。
impl<W> FtpLineDataReceiver for ChunkedListWriter<'_, W>
where
    W: AsyncWrite + Send + Unpin,
{
    async fn recv_line(&mut self, line: &str) {
        self.active = true;

        if self.buf_cap - self.buf_len < line.len()
            && let Err(e) = self.send_buf().await
        {
            self.io_error = Some(e);
            return;
        }

        self.buf.extend_from_slice(line.as_bytes());
        self.buf_len += line.len();
    }

    #[inline]
    fn should_return_early(&self) -> bool {
        self.io_error.is_some()
    }
}

/// chunked 模式的 ListWriter 实现
impl<W> ListWriter for ChunkedListWriter<'_, W>
where
    W: AsyncWrite + Send + Unpin,
{
    #[inline]
    fn take_io_error(&mut self) -> Option<io::Error> {
        self.io_error.take()
    }

    /// 刷出剩余数据并写出终止 chunk（"0\r\n\r\n"）
    async fn flush_buf(&mut self) -> io::Result<()> {
        if self.buf_len > CHUNKED_BUF_HEAD_RESERVED {
            self.send_buf().await?;
        }
        self.writer.write_all_flush(b"0\r\n\r\n").await
    }

    #[inline]
    fn is_idle(&self) -> bool {
        !self.active
    }

    #[inline]
    fn reset_active(&mut self) {
        self.active = false;
    }

    #[inline]
    fn no_cached_data(&self) -> bool {
        self.buf_len <= CHUNKED_BUF_HEAD_RESERVED
    }
}

/// 无 Content-Length 的 HTTP 响应（"结尾于连接关闭"）模式的列表写出器：
/// 直接带缓冲地写给客户端，不添加 chunked 编码框架。
pub(super) struct EndingListWriter<'a, W> {
    writer: BufWriter<&'a mut W>,
    io_error: Option<io::Error>,
    active: bool, // 是否收到过数据行（空闲检测用）
}

impl<'a, W> EndingListWriter<'a, W>
where
    W: AsyncWrite + Unpin,
{
    /// 创建写出器，buf_size 为内部 BufWriter 的缓冲大小
    pub(super) fn new(writer: &'a mut W, buf_size: usize) -> Self {
        EndingListWriter {
            writer: BufWriter::with_capacity(buf_size, writer),
            io_error: None,
            active: false,
        }
    }
}

/// 逐行接收列表数据并直接写入缓冲；写错误暂存后经 should_return_early 提前终止。
impl<W> FtpLineDataReceiver for EndingListWriter<'_, W>
where
    W: AsyncWrite + Send + Unpin,
{
    async fn recv_line(&mut self, line: &str) {
        self.active = true;
        if let Err(e) = self.writer.write_all(line.as_bytes()).await {
            self.io_error = Some(e);
        }
    }

    #[inline]
    fn should_return_early(&self) -> bool {
        self.io_error.is_some()
    }
}

impl<W> ListWriter for EndingListWriter<'_, W>
where
    W: AsyncWrite + Send + Unpin,
{
    #[inline]
    fn take_io_error(&mut self) -> Option<io::Error> {
        self.io_error.take()
    }

    #[inline]
    async fn flush_buf(&mut self) -> io::Result<()> {
        self.writer.flush().await
    }

    #[inline]
    fn is_idle(&self) -> bool {
        !self.active
    }

    #[inline]
    fn reset_active(&mut self) {
        self.active = false;
    }

    #[inline]
    fn no_cached_data(&self) -> bool {
        self.writer.buffer().is_empty()
    }
}
