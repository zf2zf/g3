/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

use anyhow::anyhow;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use g3_io_ext::{StreamCopy, StreamCopyError};
use g3_types::net::{ProxyProtocolEncodeError, ProxyProtocolV2Encoder};

use super::{DetourAction, StreamDetourContext};
use crate::config::server::ServerConfig;
use crate::serve::{ServerTaskError, ServerTaskResult};

// 单个任务的引流数据面：与检测服务之间的四条 QUIC 流（north/south 各一个收发方向），
// 以及对它们做的两件事——先取裁决（check_detour_action），裁决为继续时双向中继流量（relay）。

/// 一次任务在检测服务上占用的流资源。
///
/// 方向约定：north 是客户端侧通道（客户端 -> 服务 -> 上游），
/// south 是上游侧通道（上游 -> 服务 -> 客户端）。
pub(crate) struct StreamDetourStream {
    pub(super) north_send: SendStream,
    pub(super) north_recv: RecvStream,
    pub(super) south_send: SendStream,
    pub(super) south_recv: RecvStream,
    // 服务下线时任务用它请求关闭整条 QUIC 连接；drop 即表示本流不再使用连接
    pub(super) force_quit_sender: mpsc::Sender<()>,
    pub(super) match_id: u16, // 与检测服务约定的请求标识，响应中需回显
}

impl StreamDetourStream {
    /// 放弃本流：先显式 finish 两个发送方向，让已写入的数据能被服务收到，
    /// 然后整个流对象（含接收方向）随之释放。用于 Bypass / Block 这类不需要中继的分支。
    pub(crate) fn finish(mut self) {
        let _ = self.north_send.finish();
        let _ = self.south_send.finish();
    }
}

impl<SC> StreamDetourContext<'_, SC>
where
    SC: ServerConfig,
{
    /// 在客户端、上游、检测服务三者之间中继流量。
    ///
    /// 四条拷贝链路并发运行（biased 保证按代码顺序轮询，行为可预期）：
    ///   clt_to_d : 客户端 -> north_send
    ///   d_to_ups : north_recv -> 上游
    ///   ups_to_d : 上游 -> south_send
    ///   d_to_clt : south_recv -> 客户端
    ///
    /// 任一链路先结束就说明本次转发结束：先按结束原因做好半关闭收尾（把已排队的
    /// 数据送完再关闭对应写方向），再返回描述结束原因的 ServerTaskError。
    /// 注意正常结束也返回 Err（ClosedByClient / ClosedByUpstream）：
    /// 这类变体描述任务的结束原因，供上层记日志与统计，并不表示内部故障。
    pub(crate) async fn relay<CR, CW, UR, UW>(
        self,
        mut clt_r: CR,
        mut clt_w: CW,
        mut ups_r: UR,
        mut ups_w: UW,
        d_stream: StreamDetourStream,
    ) -> ServerTaskResult<()>
    where
        CR: AsyncRead + Unpin,
        CW: AsyncWrite + Unpin,
        UR: AsyncRead + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let StreamDetourStream {
            mut north_send,
            mut north_recv,
            mut south_send,
            mut south_recv,
            force_quit_sender,
            match_id: _, // 裁决阶段已用于校验，中继阶段不再需要
        } = d_stream;

        let copy_config = self.server_config.limited_copy_config();

        // 四条拷贝链路的命名以 d（detour 服务）为准
        let mut clt_to_d = StreamCopy::new(&mut clt_r, &mut north_send, &copy_config);
        let mut d_to_ups = StreamCopy::new(&mut north_recv, &mut ups_w, &copy_config);
        let mut ups_to_d = StreamCopy::new(&mut ups_r, &mut south_send, &copy_config);
        let mut d_to_clt = StreamCopy::new(&mut south_recv, &mut clt_w, &copy_config);

        let mut idle_interval = self.idle_wheel.register();
        let mut idle_count = 0;

        // 收尾函数的选取依据是"哪一端先结束"：
        // - relay_after_client_closed：客户端方向没了，通知服务并继续把服务剩余数据送完给上游；
        // - relay_after_remote_closed：上游方向没了，通知服务并继续把服务剩余数据送完给客户端；
        // - relay_after_detour_failed：服务侧没了（断开或读写失败），放弃该通道，
        //   只把已排队的剩余数据分别冲给上游和客户端。
        loop {
            tokio::select! {
                biased;

                r = &mut clt_to_d => {
                    return match r {
                        Ok(_) => {
                            self.relay_after_client_closed(north_send, south_send, d_to_ups).await;
                            Err(ServerTaskError::ClosedByClient)
                        },
                        Err(StreamCopyError::ReadFailed(e)) => {
                            self.relay_after_client_closed(north_send, south_send, d_to_ups).await;
                            Err(ServerTaskError::ClientTcpReadFailed(e))
                        },
                        Err(StreamCopyError::WriteFailed(e)) => {
                            self.relay_after_detour_failed(south_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("write client data to detour service failed: {e}")
                                )
                            )
                        },
                    };
                }
                r = &mut d_to_ups => {
                    return match r {
                        Ok(_) => {
                            self.relay_after_detour_failed(south_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("client connection closed by detour service")
                                )
                            )
                        },
                        Err(StreamCopyError::ReadFailed(e)) => {
                            self.relay_after_detour_failed(south_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("read client data from detour service failed: {e}"),
                                )
                            )
                        },
                        Err(StreamCopyError::WriteFailed(e)) => {
                            self.relay_after_remote_closed(north_send, south_send, d_to_clt).await;
                            Err(ServerTaskError::UpstreamWriteFailed(e))
                        },
                    };
                }
                r = &mut ups_to_d => {
                    return match r {
                        Ok(_) => {
                            self.relay_after_remote_closed(north_send, south_send, d_to_clt).await;
                            Err(ServerTaskError::ClosedByUpstream)
                        },
                        Err(StreamCopyError::ReadFailed(e)) => {
                            self.relay_after_remote_closed(north_send, south_send, d_to_clt).await;
                            Err(ServerTaskError::UpstreamReadFailed(e))
                        },
                        Err(StreamCopyError::WriteFailed(e)) => {
                            self.relay_after_detour_failed(north_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("write remote data to detour service failed: {e}"),
                                )
                            )
                        },
                    };
                }
                r = &mut d_to_clt => {
                    return match r {
                        Ok(_) => {
                            self.relay_after_detour_failed(north_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("remote connection closed by detour service")
                                )
                            )
                        },
                        Err(StreamCopyError::ReadFailed(e)) => {
                            self.relay_after_detour_failed(north_send, d_to_ups, d_to_clt).await;
                            Err(
                                ServerTaskError::InternalAdapterError(
                                    anyhow!("read remote data from detour service failed: {e}"),
                                )
                            )
                        },
                        Err(StreamCopyError::WriteFailed(e)) => {
                            self.relay_after_client_closed(north_send, south_send, d_to_ups).await;
                            Err(ServerTaskError::ClientTcpWriteFailed(e))
                        },
                    };
                }
                n = idle_interval.tick() => {
                    // n 为本次 tick 计入的空闲周期数（一次 tick 可能覆盖多个周期，故累加而非 +1）
                    if clt_to_d.is_idle() && d_to_clt.is_idle() && ups_to_d.is_idle() && d_to_ups.is_idle() {
                        idle_count += n;

                        if let Some(user) = self.task_notes.user()
                            && user.is_blocked() {
                                return Err(ServerTaskError::CanceledAsUserBlocked);
                            }

                        if idle_count >= self.max_idle_count {
                            return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                        }
                    } else {
                        // 任一方向还有流量，就重新计时
                        idle_count = 0;

                        clt_to_d.reset_active();
                        d_to_ups.reset_active();
                        ups_to_d.reset_active();
                        d_to_clt.reset_active();
                    }

                    // 用户封禁状态可能在任务运行期间变化，因此每次 tick 都要复查（与是否空闲无关）
                    if let Some(user) = self.task_notes.user()
                        && user.is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }

                    // 服务器强制下线：通知连接层关闭整条 QUIC 连接（同连接上的其它流也随之结束）
                    if self.server_quit_policy.force_quit() {
                        let _ = force_quit_sender.try_send(());
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            };
        }
    }

    /// 编码客户端方向的 PPv2 头：携带检测服务裁决所需的全部信息
    /// （会话地址、用户、任务 ID、目标上游、请求标识、协议名、附加数据长度）。
    fn encode_client_ppv2(
        &self,
        match_id: u16,
    ) -> Result<ProxyProtocolV2Encoder, ProxyProtocolEncodeError> {
        let mut ppv2 = ProxyProtocolV2Encoder::new_tcp(
            self.task_notes.client_addr,
            self.task_notes.server_addr,
        )?;
        if let Some(name) = self.task_notes.raw_username() {
            ppv2.push_username(name)?;
        }
        ppv2.push_task_id(self.task_notes.task_id().as_bytes())?;
        ppv2.push_upstream(self.upstream)?;
        ppv2.push_match_id(match_id)?;
        ppv2.push_protocol(self.protocol.as_str())?;
        // 附加数据长度告知服务侧随后要读取多少字节，因此头必须先于 payload 发出
        ppv2.push_payload_len(self.payload.len())?;
        Ok(ppv2)
    }

    /// 编码上游方向的 PPv2 头：只需请求标识即可与前面的裁决请求对应上。
    fn encode_remote_ppv2(
        &self,
        match_id: u16,
    ) -> Result<ProxyProtocolV2Encoder, ProxyProtocolEncodeError> {
        let mut ppv2 = ProxyProtocolV2Encoder::new_tcp(
            self.task_notes.client_addr,
            self.task_notes.server_addr,
        )?;
        ppv2.push_match_id(match_id)?;
        Ok(ppv2)
    }

    /// 向检测服务发起裁决请求并等待结果。
    ///
    /// 报文顺序：north 上发送客户端 PPv2 头（+ 可选附加数据）→ 读取 4 字节响应
    /// （前 2 字节回显 match_id，后 2 字节为动作）→ 仅当裁决为 Continue 时，
    /// 才在 south 上发送上游方向的头，把上行数据通道也打通。
    ///
    /// 失败（写失败、match_id 不匹配、超时）返回 Err，调用方按内部错误终止任务。
    pub(crate) async fn check_detour_action(
        &self,
        detour_stream: &mut StreamDetourStream,
    ) -> anyhow::Result<DetourAction> {
        let mut client_ppv2 = self
            .encode_client_ppv2(detour_stream.match_id)
            .map_err(|e| anyhow!("failed to encode ppv2 header for client stream: {e}"))?;
        detour_stream
            .north_send
            .write_all(client_ppv2.finalize())
            .await
            .map_err(|e| anyhow!("failed to send ppv2 header for client stream: {e}"))?;
        if !self.payload.is_empty() {
            detour_stream
                .north_send
                .write_all(&self.payload)
                .await
                .map_err(|e| anyhow!("failed to send payload data: {e}"))?;
        }
        // no flush needed on SendStream

        let detour_action;

        let mut buf = [0u8; 4];
        match tokio::time::timeout(
            self.request_timeout,
            detour_stream.north_recv.read_exact(&mut buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                let rsp_match_id = u16::from_be_bytes([buf[0], buf[1]]);
                if rsp_match_id != detour_stream.match_id {
                    return Err(anyhow!(
                        "invalid response from detour server: invalid match id"
                    ));
                }
                let action = u16::from_be_bytes([buf[2], buf[3]]);
                detour_action = DetourAction::from(action);
                if detour_action != DetourAction::Continue {
                    return Ok(detour_action);
                }
            }
            Ok(Err(e)) => return Err(anyhow!("failed to get response from detour server: {e}")),
            Err(_) => return Err(anyhow!("timed out to get response from detour server")),
        }

        let mut remote_ppv2 = self
            .encode_remote_ppv2(detour_stream.match_id)
            .map_err(|e| anyhow!("failed to encode ppv2 header for remote stream: {e}"))?;
        detour_stream
            .south_send
            .write_all(remote_ppv2.finalize())
            .await
            .map_err(|e| anyhow!("failed to send ppv2 header for remote stream: {e}"))?;
        // no flush needed on SendStream

        Ok(detour_action)
    }

    /// 客户端先结束时的收尾：向服务关闭两个发送方向，
    /// 然后把服务仍要回给上游的数据搬完，最后半关闭上游写端。
    ///
    /// finish() 成功说明服务已收到完整的结束通知，可以等数据搬完；
    /// 失败时退化为只 flush 已排队的部分（尽力送出，不再等待读完）。
    async fn relay_after_client_closed<UW>(
        self,
        mut north_send: SendStream,
        mut south_send: SendStream,
        mut d_to_ups: StreamCopy<'_, RecvStream, UW>,
    ) where
        UW: AsyncWrite + Unpin,
    {
        let _ = south_send.finish();
        let shutdown = match north_send.finish() {
            Ok(_) => (&mut d_to_ups).await.is_ok(),
            Err(_) => d_to_ups.write_flush().await.is_ok(),
        };
        if shutdown {
            let _ = d_to_ups.writer().shutdown().await;
        }
    }

    /// 上游先结束时的收尾：与客户端分支对称，剩余数据回给客户端后关闭客户端写端。
    async fn relay_after_remote_closed<CW>(
        self,
        mut north_send: SendStream,
        mut south_send: SendStream,
        mut d_to_clt: StreamCopy<'_, RecvStream, CW>,
    ) where
        CW: AsyncWrite + Unpin,
    {
        let _ = north_send.finish();
        let shutdown = match south_send.finish() {
            Ok(_) => (&mut d_to_clt).await.is_ok(),
            Err(_) => d_to_clt.write_flush().await.is_ok(),
        };
        if shutdown {
            let _ = d_to_clt.writer().shutdown().await;
        }
    }

    /// 检测服务侧不可用时的收尾：放弃与服务的通道（finish 仍可用的那个发送端），
    /// 只把已经在途的数据分别冲给上游和客户端，然后各自半关闭。
    ///
    /// 与上面两个分支不同，这里不等待读完——读的源头（服务流）已经废了。
    async fn relay_after_detour_failed<CW, UW>(
        self,
        mut left_sender: SendStream, // 尚未失败、还可以发出结束通知的那一侧
        mut d_to_ups: StreamCopy<'_, RecvStream, UW>,
        mut d_to_clt: StreamCopy<'_, RecvStream, CW>,
    ) where
        CW: AsyncWrite + Unpin,
        UW: AsyncWrite + Unpin,
    {
        let _ = left_sender.finish();
        if d_to_ups.write_flush().await.is_ok() {
            let _ = d_to_ups.writer().shutdown().await;
        }
        if d_to_clt.write_flush().await.is_ok() {
            let _ = d_to_clt.writer().shutdown().await;
        }
    }
}
