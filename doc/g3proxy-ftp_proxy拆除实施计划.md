# g3proxy ftp_proxy 原生网关拆除实施计划

> 配套阅读：[g3proxy-ftp_proxy模块架构评审与改进方向](g3proxy-ftp_proxy模块架构评审与改进方向.md)（问题定性）、
> [etc-ftp配置业务流程分析](etc-ftp配置业务流程分析.md)（部署事实）。
> 分支：`local/work-v113`。决策日期：2026-11-12。
> 本文是实施计划（spec 即本文 + 上述评审文档），按 Task 1–5 顺序执行，每个 Task 一个 commit。

---

## 1. 背景与决策

评审文档的结论：`serve/ftp_proxy/` 的 server 外壳形态合规，但 `ctl_common` / `upload_state`
被 `inspect/ftp`、`inspect/tls`、`inspect/start_tls`、`serve/http_proxy/task/connect` 反向引用，
依赖方向倒置（`serve/mod.rs` 中唯一 `pub(crate)` 的 server 模块）；`connect_bridge.rs` 为零引用孤儿。

部署事实（本次核实）：`etc/g3proxy/ftp/` 与 `etc/g3proxy/http/` 的 server 配置**全部**是
`type: http_proxy`，原生网关只在 `examples/hybrid_ftp_proxy/` 示例中出现，生产中整体休眠。
运行时 FTP 流量唯一路径：

```
FTP 客户端 → HTTP CONNECT 3128 → http_proxy/task/connect
           → inspect/stream、inspect/tls → inspect/ftp
           → serve::ftp_proxy::{ctl_common, upload_state}   ← 仅这两个文件被真正使用
```

**决策（负责人拍板）：只保留正向代理 CONNECT 路径。** 原生 FTP 网关能力整体移除：

- `ctl_common.rs` → `inspect/ftp/ctl.rs`（协议解析原语，含全部单元测试，随迁）
- `upload_state.rs` → `inspect/ftp/upload_state.rs`（跨连接协议状态）
- `serve/ftp_proxy/` 其余文件（server/task/stats/connect_bridge/mod）删除
- `config/server/ftp_proxy.rs` 及注册链删除
- `examples/hybrid_ftp_proxy/` 删除

与评审文档的关系：落实其 P0（删 connect_bridge），并超出其 P1——评审建议保留原生 server
外壳，本决策连外壳一并撤掉。**P2（全局状态改造）、P3（DPI 判定统一等）不在本次范围。**
附带收益：评审 §6-7（`upstream_ip` 恒为 0.0.0.0）、§10-4（PASV 改写写回 127.0.0.1）等
原生路径已知 bug 随删除一并消失。

## 2. 目标形态与验收标准

```
g3proxy/src/inspect/ftp/
  mod.rs          ← 增加 ctl / upload_state 两个模块声明
  ctl.rs          ← 原 serve/ftp_proxy/ctl_common.rs（含单元测试）
  upload_state.rs ← 原 serve/ftp_proxy/upload_state.rs
  object.rs / upload_data.rs ← 仅改 import

g3proxy/src/serve/              ← 不再有 ftp_proxy 目录
g3proxy/src/config/server/      ← 不再有 ftp_proxy.rs
```

依赖全部向下：`serve → inspect`，无回边。

验收标准（全部满足才算完成）：

1. `grep -rn "ftp_proxy\|FtpProxy" g3proxy/src/` 零命中
2. `cargo check -p g3proxy --all-targets` 通过
3. `cargo clippy -p g3proxy --tests -- -D warnings` 通过（仓库硬门槛）
4. `cargo test --lib -p g3proxy` 全绿（含随迁的 ctl 单元测试，当前 44 个 `#[test]`）
5. 配置 `type: ftp_proxy` 变为未知类型报错（预期行为变化，唯一外部可见变化）

## 3. 全局约束

- 每个 commit 后代码库可编译；纯搬迁 + 删除，**不改 CONNECT 路径任何运行行为**。
- 不动：路径 A（`http_proxy/task/ftp/`，FTP-over-HTTP 翻译）、`lib/g3-ftp-client`、
  `module/ftp_over_http`、`etc/g3proxy/ftp/`（本就是 http_proxy 配置）、`etc/g3fcgen/ftp/`、
  `examples/ftp_over_http_connect/`、`utils/ftp`（独立 CLI，无主库依赖）。
- 保留文件 SPDX 头；注释沿用中英双语惯例；模块文档随职责变化更新，不新增多余注释。
- 不碰未跟踪文件：`doc/research-vey-sync.md`、`g3proxy/utils/ftp/README.md`。
- 搬迁用 `git mv` 保留历史；删除用 `git rm`。
- doc/ 下历史文档（含评审文档）不回改，保留为历史记录。

## Task 1: upload_state 下沉到 inspect/ftp

`upload_state` 在 `serve/ftp_proxy/` 内部无任何消费者（已核实），只被外部 5 个文件引用。

步骤：

1. `git mv g3proxy/src/serve/ftp_proxy/upload_state.rs g3proxy/src/inspect/ftp/upload_state.rs`
2. `g3proxy/src/serve/ftp_proxy/mod.rs`：删除 `upload_state` 模块声明及其注释。
3. `g3proxy/src/inspect/ftp/mod.rs`：增加 `pub(crate) mod upload_state;`（带一行中文模块注释，
   沿用现有风格）。
4. 改 import（共 5 个文件 7 处）：
   - `inspect/ftp/object.rs:33` → `use super::upload_state::get_ftp_upload_state;`；
     `:314` 内联路径 → `super::upload_state::get_ftp_upload_state()`
   - `inspect/ftp/upload_data.rs:25` → `use super::upload_state::{PendingUploadInfo, get_ftp_upload_state};`；
     `:10` 文档链接 → `crate::inspect::ftp::upload_state`
   - `inspect/tls/modern.rs:132` → `crate::inspect::ftp::upload_state::get_ftp_upload_state()`
   - `inspect/start_tls/tls.rs:141` → 同上
   - `serve/http_proxy/task/connect/task.rs:31` → `use crate::inspect::ftp::upload_state::get_ftp_upload_state;`
5. 验证：`cargo check -p g3proxy --all-targets`
   Expected: 编译通过，无 error。
6. 验证：`grep -rn "serve::ftp_proxy::upload_state" g3proxy/src/`
   Expected: 零命中。
7. Commit：`g3proxy: move FTP upload state to inspect::ftp::upload_state`

## Task 2: ctl_common 下沉为 inspect/ftp/ctl.rs

步骤：

1. `git mv g3proxy/src/serve/ftp_proxy/ctl_common.rs g3proxy/src/inspect/ftp/ctl.rs`
2. `serve/ftp_proxy/mod.rs`：删除 `ctl_common` 声明及注释；
   `inspect/ftp/mod.rs`：增加 `pub(crate) mod ctl;`（带模块注释）。
3. 重写 `ctl.rs` 模块文档：不再提"原生任务与 CONNECT 桥共用"（两者即将删除），
   改为"FTP 控制通道解析与 PASV/EPSV 应答改写原语"（中英双语，保留 SPDX 头）。
4. 改 import：
   - `inspect/ftp/object.rs:30-32` → `use super::ctl::{is_auth_tls_command, is_upload_command, parse_upload_command, read_ftp_response};`
   - `serve/ftp_proxy/task.rs:33-37` 与 `connect_bridge.rs:39-42`：
     `use super::ctl_common::{…}` → `use crate::inspect::ftp::ctl::{…}`（临时改动，Task 3 随文件删除）
5. 验证：`cargo test --lib -p g3proxy inspect::ftp`
   Expected: 随迁单元测试全部通过（当前 44 个 `#[test]`，以实际输出为准），无 fail。
6. 验证：`cargo check -p g3proxy --all-targets`
   Expected: 编译通过。
7. Commit：`g3proxy: move FTP control-channel parsing to inspect::ftp::ctl`

## Task 3: 删除原生 FTP 网关 server 与配置

步骤：

1. `git rm -r g3proxy/src/serve/ftp_proxy/`（剩余 mod/server/task/stats/connect_bridge 五文件）
2. `git rm g3proxy/src/config/server/ftp_proxy.rs`
3. `serve/mod.rs:33`：删除 `pub(crate) mod ftp_proxy;`
4. `serve/ops.rs`：删除 `:29` 的 `use super::ftp_proxy::FtpProxyServer;` 与
   `:313` 的 `AnyServerConfig::FtpProxy(c) => …` 分支
5. `config/server/mod.rs`：删除 `:25` mod 声明、`:135` `FtpProxy(…)` 枚举变体、
   `:207-210` `"ftp_proxy" | "ftpproxy"` 解析分支
6. `serve/audit_bridge.rs:68-74`：`UploadAuditContext` 注释中
   "FTP callers build it in `serve/ftp_proxy/task.rs`" 改为指向 `inspect/ftp/upload_data.rs`
   （删除后仅存的 FTP 调用方，中英文两行都改）。
7. 验证：`cargo check -p g3proxy --all-targets`
   Expected: 编译通过；允许出现 `run_upload_audit_or_relay` 的 dead_code 警告（Task 4 处理）。
8. 验证：`grep -rn "FtpProxy\|ftp_proxy" g3proxy/src/`
   Expected: 零命中。
9. Commit：`g3proxy: remove the native FTP gateway server`

## Task 4: audit_bridge 死代码清扫

`run_upload_audit_or_relay`（单向版，`audit_bridge.rs:107`）的唯二调用方
（native task、connect_bridge）已在 Task 3 删除；CONNECT 路径用的是 `_bidi` 版，保留。

步骤：

1. 跑 `cargo check -p g3proxy 2>&1 | grep -A3 dead_code` 收集死代码清单，
   删除 `run_upload_audit_or_relay` 及仅被它使用的私有 helper
   （`audit_and_forward` / `raw_forward_with_idle` 若与 bidi 版共享则保留，以警告为准）。
2. 验证：`cargo clippy -p g3proxy --tests -- -D warnings`
   Expected: 零警告通过。
3. Commit：`g3proxy: drop the upload audit relay left unused by the gateway removal`

## Task 5: 删除 hybrid 示例、CHANGELOG、全量验证

步骤：

1. `git rm -r g3proxy/examples/hybrid_ftp_proxy/`
2. `g3proxy/CHANGELOG`：按现有格式在顶部版本段加一条
   ` - Removed: the native FTP gateway server (type ftp_proxy); FTP upload audit is served by the HTTP CONNECT forward proxy only`
   （若本地已有 unreleased 段则加入该段，实施时以文件实际格式为准）。
3. 验证：`cargo test --lib -p g3proxy`
   Expected: 全绿。
4. 验证：`cargo clippy -p g3proxy --tests -- -D warnings`
   Expected: 零警告。
5. 验证：`grep -rln "ftp_proxy\|FtpProxy" g3proxy/ --include=*.rs --include=*.yaml --include=*.toml --include=*.sh`
   Expected: 零命中（doc/ 历史文档除外）。
6. Commit：`g3proxy: remove the hybrid FTP proxy example`

## 4. 运行时回归（人工，不在本会话执行）

本环境无在线 FTP/ICAP 服务，以下为交付后的人工验证步骤：

1. 用 `etc/g3proxy/ftp/` 配置启动 g3proxy（http_proxy 监听 3128）。
2. 明文 FTP 上传审计：`curl -x http://127.0.0.1:3128 -T ./test.bin ftp://user:pass@ftp服务器/incoming/test.bin`
   预期：上传成功，ICAP REQMOD 审计记录含正确文件名（`STOR` 路径含空格/中文也要试）。
3. FTPS（AUTH TLS）上传 + vsftpd `require_ssl_reuse`：确认数据通道 TLS 会话复用仍生效
   （`upload_state` 的 session 表是这条链路的命脉，重点验）。
4. 对照：`g3proxy/utils/ftp` 的 `g3proxy-ftp` CLI **不能**用于此回归（直连 FTP、不会 CONNECT），
   只能直连真实服务器做对照；详见其 README。
5. 旧配置 `type: ftp_proxy` 启动应报未知 server 类型错误（预期行为变化）。

## 5. 风险与回滚

- 风险低：被删能力本就不在部署中运行；搬迁是纯 import 变更，单测随迁兜底。
- 唯一外部可见变化：`type: ftp_proxy` 配置从可加载变为报错——这正是目标。
- 回滚：每个 Task 独立 commit，`git revert` 即可；删除的代码 git 历史可找回。

## 6. Review Focus（终审关注点，现有测试覆盖不到）

- 搬迁是否改变可见性或语义：`pub(crate)` 级别、`OnceLock` 单例初始化参数、TTL/容量常量必须原样。
- `audit_bridge` 清扫是否误删与 bidi 版共享的 helper。
- 删除后 `type: ftp_proxy` 的报错路径是否落入正常的未知类型分支。
- 注释/文档链接是否残留指向已删文件的引用（`serve/ftp_proxy/task.rs` 等）。
- CONNECT 路径行为不变性：connect/task.rs 只允许 import 行变化。