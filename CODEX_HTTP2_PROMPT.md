# Codex 执行 Prompt：http_fetch HTTP/2 指纹模拟与长连接重构

你正在 `gsmlg-dev/http_fetch` 仓库工作。请直接完成代码、测试与文档，不要只给建议或生成另一个计划。

## 任务

以 `docs/HTTP2_IMPLEMENTATION_PLAN.md`（随附的同名文件）为实施规范，把现有 HTTP/2 路径升级为：

**具有可配置、可观测、可验证 HTTP/2 wire fingerprint 的长连接客户端，同时支持 profile 隔离的连接复用、多 stream、连接级 HPACK、背压流式上传、HTTPS h2 与 h2c prior knowledge。**

这些是同一次重构的共同目标。不要先完成连接池，最后才通过几个 SETTINGS 选项补“指纹支持”。不要把返回 Akamai 风格 hash 当成完成模拟。

评审基线是 `b4ad2f5ef003415941b97f5e0cc78c21dcc94296` / v0.13.0，但实际工作分支可能已更新。先记录当前 HEAD、工作区差异和已存在的实现；保留用户改动，不得 reset 到评审 SHA。若计划文件尚未落盘，先从随附内容保存；以下要求也是必须遵守的执行契约。

## 1. 先阅读实际代码

阅读根目录与作用域内的 AGENTS.md、README、mix.exs、mix.lock、CI，以及：

- `apps/http_core/lib/http/http2.ex`
- `apps/http_core/lib/http/http2/frame.ex`
- `apps/http_core/lib/http/http2/hpack.ex`
- `apps/http_core/lib/http/headers.ex`、`request.ex`、transport 模块
- `apps/http_fetch/lib/http/socket_client.ex`
- `apps/http_fetch/lib/http/fetch_options.ex`
- `apps/http_fetch/lib/http/stream.ex`、Response、Promise、AbortController 与 application supervisor
- `apps/http_fetch/test/http/socket_client_http2_test.exs` 及现有 streaming/ex_ssl/redirect 测试

现有实现有单 stream/单请求路径、固定初始化与 HPACK 编码；以实际文件为准，不把过期文档当作真相。TLS profile API 必须核实锁定版本的 ex_ssl，不能照猜测名称调用。

## 2. 不可违反的架构与兼容性要求

### A. 协议核心和 OTP 边界

`http_core` 保持纯函数协议状态转换，分离 Connection 和 StreamState。`http_fetch` 提供每连接一个长期 ConnectionOwner（建议 `:gen_statem`）、有界 Pool 和请求适配器/BodyBridge。不要让 core 反向依赖 Fetch 的 PID stream、Promise 或 Response。

连接 owner 持有一份连接级 encoder 和一份 decoder、local/peer SETTINGS、连接流控和 stream registry。stream 独立维护窗口、状态、body 与 deadline。只有一个有序 writer，HPACK 编码提交顺序必须与实际写入顺序一致。

HEADERS/CONTINUATION 不可被其他帧打断。取消不能随意丢弃已改变共享 HPACK 状态的首部块；被应用放弃的入站首部仍要按规范维护压缩上下文。

### B. WireProfile 必须真实生效

实现声明式、版本化、有限且可校验的 WireProfile，覆盖：

- 有序 SETTINGS，包括省略字段与显式默认值的区别；禁止先转 map/sort/deduplicate 后破坏 wire 顺序。
- 初始连接 WINDOW_UPDATE、合法初始化帧顺序、接收窗口及阈值/批量补充策略。
- 伪首部顺序、普通首部顺序、重复字段和默认 UA/body 首部的插入位置。
- HPACK Huffman、静态/动态索引、表容量更新、never-index 与敏感字段策略。
- legacy PRIORITY / HEADERS priority，以及 RFC 9218 的 Priority、PRIORITY_UPDATE 和协商约束。
- HEADERS/CONTINUATION 分片、DATA 分块/有限合并与合法 padding。

Profile 不能覆盖证书校验、协议正确性、peer constraints 或资源上限。初始连接窗口不是 stream 窗口，也不是 WINDOW_UPDATE 增量。local/peer table、frame、window、concurrency 限制必须按方向建模，所有宣告的能力要有真实处理能力。

默认提供有版本的原生 profile 和至少两个明确标记为 synthetic 的测试 profile。需要 push-enabled/省略 ENABLE_PUSH 的 profile 时，先实现有界 PUSH_PROMISE 解码/拒收并保持 HPACK 同步；不需要新增应用级 push API。

### C. Profile-aware 连接池

PoolKey 至少包含同 origin、实际协议/路由、TLS backend 和有效安全配置/mTLS 身份、已解析 TLS profile、完整 HTTP/2 profile digest、显式身份 scope，以及不能安全共享的连接参数。

不能只按 host、profile 名称或 Akamai hash 复用。Profile 连接创建后不可变；同名不同内容不得误复用；有序 wire 配置参与 digest。证书/CA 同路径更新要有内容身份或配置代次。不要把凭据、私钥或 ticket 写进日志。

池原子预留 stream 容量，握手不能阻塞池进程；有界排队、连接数/并发上限、idle/drain timeout。单个等待者取消不影响其他等待者。请求结束释放 stream，不关闭健康共享连接。提供独立连接模式用于冷连接观察。

### D. 流式上传和消费者隔离

延续现有 `body: stream_pid`、`HTTP.Stream.from_enumerable` 和 `duplex: :half` / `"half"`，不要发明不兼容的新上传 API。

禁止把整个流式 body 转为 binary/list。仅在有读取信用和缓冲预算时继续拉取。应用 chunk 不等于 DATA frame；由调度器按 profile、两级窗口、peer frame limit 和 padding 成本决定分帧。

ConnectionOwner 不能同步等待 `HTTP.Stream.chunk/3`、应用读取或生产者供给。实现有界的上传/响应桥接或信用通道，明确最大 chunk、单消费者/ACK 合同及所有保留字节的预算。慢 producer/consumer 不应人为卡住其他健康 stream。

处理 EOF、空 chunk、长度校验/明确拒绝、提前最终响应、生产者异常、消费者退出及 cancellation。未知长度的 H2 上传不得使用 HTTP/1.1 chunk framing。不要通过保留巨型 binary 的 sub-binary 或把队列转移到另一个 mailbox 伪称有界。

### E. 生命周期与安全

单次取消/超时通常只取消对应 queue entry/stream；连接级错误才终止所有流。保留 Promise/Response/AbortController 约定，不能让 Promise 内部 Task 的正常结束终止仍待消费的响应。

分开 request、queue、connect、SETTINGS、write-stall、idle/drain 计时器。GOAWAY 停止接纳新流并正确排空；处理 last_stream_id 和多次 GOAWAY。默认不自动重放任何已提交请求。流式 307/308 不得重新消费已经用过的 body。

保留 ex_ssl 跨 TLS record / peer close 后排空明文的回归语义。只完成确有合法完成标记的 stream；截断、必需 DATA 写失败、取消与超时不能改成成功。

TLS 默认仍为 OTP `:ssl`，`:ex_ssl` 显式选择；不关闭验证，不静默回退，不擅自修改 ex_ssl 仓库。TLS session cache 无法按身份隔离时拒绝不安全组合或要求明确关闭恢复，不偷偷跨身份共享。

### F. 公开选项与协议选择

保持 flat fetch init。建议新增 `http2_profile`、`http2_reuse`、`http2_scope`、`http2_priority`；名称可在初始 ADR 中统一调整，但语义不能缩水。

所有新选项必须贯穿 FetchOptions、Request、PoolKey 与实际序列化；未知 `http2_*`/profile 字段和不适用组合明确报错，不能静默忽略。保持缺省 `:http1`；HTTP `:auto` 仍为 HTTP/1.1。

HTTPS `:auto` 没有显式 profile 时保持原 ALPN 行为；显式指定 HTTP/2 profile 时严格要求 h2，否则明确失败。h2c 使用相同核心，不新增 Upgrade 流程。

## 3. 指纹验收不是单元测试自证

实现与 profile compiler 分离的有界分片观察器、结构化 observation、Akamai 风格有损摘要与字段级 diff。区分 `planned`、`serialized`、`transport_send_ok`、`peer_observed`；send 成功不表示服务端已经观测到。

验证冷连接的初始化，也验证复用后的第二/第三请求、并发 stream、HPACK 演变和上传行为。默认不记录原始敏感首部块；raw capture 必须显式、限量、限时且不进入普通日志。

使用至少一个独立成熟 HTTP/2 实现验证实际字节与 HPACK。固定测试依赖版本，不以本库编码器生成全部“外部正确样本”。

真实浏览器 profile 必须有具体产品/版本/平台、采集场景、工具/样本来源、冷/热连接上下文、manifest、fixture digest 和明确匹配范围。合成值或第三方模拟器输出不能标为真实浏览器抓包。

分别报告 `engine_verified` 与 `browser_profile_verified`。环境拿不到真实样本时继续完成引擎、导入/采集/比较工具和合成测试，把目标样本项标为未验证；不得编造参数或宣布完整浏览器模拟已经验证。

## 4. 执行顺序

依次完成，并在计划中更新状态：

P0：工作区/基线审计、行为矩阵、ADR、回归基线。
P1：WireProfile/compiler/digest、HeaderPolicy、初始化、独立 byte fixtures。
P2：持久 Connection/StreamState、SETTINGS/流控、连接级 HPACK、优先级与 push 拒收。
P3：ConnectionOwner、有序 writer、profile-aware Pool、预留/排队/取消/drain。
P4：背压流式上传、响应桥接、公平调度和完整内存预算。
P5：观察/diff、冷/热/并发指纹验证、真实 profile 导入与采集证据。
P6：API 集成、后端/协议回归、互操作与压力测试、文档和完成报告。

不要停在架构文档或 skeleton。阶段内优先写暴露缺口的测试，再实现，再跑回归；遇到具体环境障碍继续完成可执行部分，报告精确障碍和未验证项。

## 5. 必测场景

完整采用计划中的验收矩阵，至少证明：一条实际 socket 连续复用且三个请求真实重叠；不同 profile/TLS/scope 隔离；容量竞争不超配；单流取消不伤邻居；窗口为零/变负时正确暂停恢复；慢生产者与慢消费者隔离；早响应停止上传；HPACK 表缩小再恢复；HEADERS 编码提交时取消；GOAWAY 不自动重放；跨 TLS record close/drain；禁用/拒收 push；未知/巨大/非法帧输入受限；h2c、OTP :ssl h2 和 ex_ssl h2；既有 HTTP/1.1 与其他 umbrella app 无回归。

从根目录按 AGENTS/实际 CI 执行：

```sh
MIX_ENV=test mix deps.get
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test apps/http_core/test
MIX_ENV=test mix test apps/http_fetch/test
mix test
mix format --check-formatted
mix credo
mix dialyzer
mix docs
```

再跑受影响 app、独立互操作和 packaged-consumer checks。不要删测、弱化断言、伪造通过或只运行新增测试。性能与内存数据只报实测，包含全部桥接/队列/binary 保留，不只报 owner heap。

## 6. 交付

提交代码与测试，并维护：

- `docs/HTTP2_IMPLEMENTATION_PLAN.md`
- `docs/HTTP2_ARCHITECTURE.md`
- `docs/HTTP2_FINGERPRINTS.md`
- `docs/HTTP2_PROFILE_CAPTURE.md`
- `docs/HTTP2_IMPLEMENTATION_REPORT.md`
- README 与 CHANGELOG 的真实支持范围、选项与迁移说明。

按阶段整理可审阅的本地 conventional commits，遵守工作区权限。不自动 push/merge/tag/release，不修改另一个仓库，不扩展 HTTP/3/QUIC、h2c Upgrade、跨 origin coalescing 或新的代理功能。

最终报告：基线 SHA、变更路径、实际 API、各阶段/验收 ID 状态、运行命令与结果、独立线级证据、browser-profile 证据等级、性能实测（若有）、仍未完成或未验证的事项。只在有相应证据时使用“通过”“已验证”。
