# http_fetch：HTTP/2 指纹可控、多路复用与流式上传实施计划

- 日期：2026-09-24
- 仓库：`gsmlg-dev/http_fetch`
- 本次核对基线：`main` / `b4ad2f5ef003415941b97f5e0cc78c21dcc94296` / v0.13.0
- 状态：P1/P2/P3 核心与显式 profile 的 h2c Fetch 接入已实现并有真实 socket
  复用、三 stream 重叠及同时冷启动去重证据；P4 已加入窗口恢复和 peer
  MAX_FRAME_SIZE 分帧回归，P5 已加入有界 provenance manifest 校验；公平调度、
  完整互操作矩阵、P6 gates 和真实浏览器样本仍在进行。
- 执行入口：配套 `CODEX_HTTP2_PROMPT.md`。

## 1. 目标与完成标准

将当前单请求 HTTP/2 路径升级为**实际 wire behavior 可配置、可观测、可验证的长连接 HTTP/2 客户端**。本次必须同时交付：HTTP/2 指纹模拟、profile 隔离的连接复用、多 stream 管理、连接级 HPACK、背压流式上传与响应隔离，以及 HTTPS h2 / cleartext h2c prior knowledge。

指纹不是附加的几个 SETTINGS 参数，也不是填写一个 hash。配置决定实际发出的协议行为，观测器从真实序列化/接收的字节生成结构化观察，独立测试端验证二者。Akamai 风格摘要仅作为一种有损投影，不得代替完整 profile 或完整验证。[R4]

两种完成状态必须分开记录：

| 状态 | 必须具备的证据 |
|---|---|
| `engine_verified` | 自定义 profile 全链路生效；冷连接、复用、并发、上传、HPACK、优先级、背压及隔离测试通过；独立实现能解析实际流量 |
| `browser_profile_verified` | 对一个明确版本/平台/采集场景的目标客户端，存在可追溯的独立样本与字段级比对；按匹配范围标记，而不是宣称整个浏览器已被复制 |

合成样本可以证明引擎能力，不能冒充浏览器样本。浏览器模拟是本项目的实际目标：必须交付目标 profile 的导入、版本化、采集与比较流程。若执行环境无法取得目标样本，仍需实现引擎与工具，并将相应 browser-profile 验收项明确标记为未验证，不得以“全部完成”掩盖。

## 2. 当前基线与需要保留的约定

基线源码呈现以下状态；执行时应先确认工作分支是否已有后续实现，不得回退用户的新代码。[S1–S7]

| 位置 | 基线行为 / 改造点 |
|---|---|
| `apps/http_core/lib/http/http2.ex` | 固定 stream 1；请求初始化与连接前言绑定；空 SETTINGS；固定伪首部顺序；收取 DATA 后立即补窗口 |
| `apps/http_core/lib/http/http2/frame.ex` | 已有基本帧 codec；扩展其校验和优先级帧支持，不另起不兼容 codec |
| `apps/http_core/lib/http/http2/hpack.ex` | 请求编码为不建立索引的字面量；已有接收解码能力，但不能直接视为成熟的持久连接 HPACK 实现 |
| `apps/http_fetch/lib/http/socket_client.ex` | 请求 owner 管理连接；结束关闭 socket；HTTP/2 拒绝流式请求体；保留 HTTP/1.1 路径及已有 TLS close/drain 回归 |
| `apps/http_fetch/lib/http/fetch_options.ex` | 扁平 fetch init 选项；默认 `:http1`；未知选项会被忽略，新 HTTP/2 选项必须显式接入并校验 |
| `apps/http_fetch/lib/http/stream.ex` | 已有 PID body、`duplex: :half` / `"half"`、生产者确认与 reader ACK；同步等待不能搬进共享连接 owner |
| `apps/http_core/lib/http/transport/ex_ssl.ex` | 通过现有 `ssl:` 选项进入 `SSL.connect/4`；继续使用 transport 抽象，不猜测已安装 ex_ssl 的 profile API |

兼容性约束：保留 `HTTP.fetch/2`、`HTTP.Promise`、`HTTP.Response`、`HTTP.AbortController` 的公开约定；以实际代码和测试为准修正文档矛盾。不得引入 `options:`、`opts:` 或 `client_opts:` 的旧式请求选项桶。[S1]

TLS 默认保持 OTP `:ssl`；`:ex_ssl` 仍显式选择。保留证书验证、主机名检查、mTLS 身份隔离、request-time backend pinning、ALPN 行为和失败可见性。不添加静默 TLS 后端回退。[S6–S7]

## 3. 范围边界

### 本次实现

| 领域 | 本次交付 |
|---|---|
| Wire profile | 有序 SETTINGS、初始化序列、窗口策略、首部顺序、HPACK 编码策略、优先级、分帧和可选 padding |
| 连接复用 | 同 origin 且相同有效连接策略/身份的连接复用；有界池、排队、空闲回收、drain、独立连接模式 |
| 多 stream | stream 生命周期、唯一 ID、容量预留、响应分派、独立取消/超时、连接级控制帧 |
| 上传 | 现有 PID/Enumerable 入口，增量读取、信用控制、有界缓冲、EOF、提前响应和生产者失败 |
| 观测 | 有界分片观察、实际线级摘要、期望/实际 diff、来源/完整性标记与脱敏 |
| 验证 | 独立协议互操作、golden bytes、冷/热连接序列、多路复用和流式压力回归 |

### 明确不扩张

本次不实现 HTTP/3/QUIC，不修改 `ex_ssl` 仓库，不把协议引擎替换成 Mint/Finch/curl，不新增 h2c Upgrade，不做跨 origin connection coalescing、代理协议扩展或 HTTP/2 over Unix socket，不新增 WebSocket extended CONNECT。现有 HTTP/1.1、WebSocket、SSE、HTTP/3/WebTransport 的已支持行为不得回归。

不添加自动重放已发出请求的通用 retry 系统，不自动发布版本、修改默认 TLS 后端、推送或合并远端分支。不承诺复制 TCP 分段、TLS record 边界、网络时序、浏览器完整行为或第三方识别系统的结果。

## 4. 架构决策

采用**纯函数协议核心 + 连接级 OTP owner + 请求级适配进程**。下列名称是建议，不是现存 API；允许根据仓库命名调整，但不能混淆状态归属。

| 层级 | 建议模块 | 职责 |
|---|---|---|
| `http_core` | `HTTP.HTTP2.WireProfile` | schema、校验、解析、不可变快照、稳定配置 digest |
| `http_core` | `HTTP.HTTP2.Connection` | 纯连接状态与输入到 effects 的转换；不调用 socket、不等待应用进程 |
| `http_core` | `HTTP.HTTP2.StreamState` | 单 stream 状态、窗口、首部/body 完成度、错误与 deadline 关联 |
| `http_core` | `HTTP.HTTP2.Settings` / `FlowControl` | 本地/对端 settings、ACK 状态、窗口记账与补充决策 |
| `http_core` | `HTTP.HTTP2.HPACK` | 保留兼容入口；内部拆分 Encoder/Decoder，两个方向各一份连接上下文 |
| `http_core` | `HTTP.HTTP2.HeaderPolicy` / `Scheduler` | 有序首部策略、可写 stream 选择、分帧计划与优先级信号 |
| `http_core` | `HTTP.HTTP2.Fingerprint` | 只观察字节，不执行 profile；输出 raw observation、摘要和 diff |
| `http_fetch` | `HTTP.HTTP2.ConnectionOwner` | 每连接一个 `:gen_statem`，独占连接状态；处理 transport 事件、计时器与有序写入 |
| `http_fetch` | `HTTP.HTTP2.Pool` / `PoolKey` | 有界匹配与预留、连接建立去重、排队和回收；不执行网络握手 |
| `http_fetch` | 请求适配器 / BodyBridge | 保持 Promise/AbortController 接口；隔离生产者与消费者等待 |

`http_core` 不得反向依赖 `http_fetch` 的 PID stream、Response、Promise 或 supervisor。应用进程事件由 runtime 适配为核心的 stream_id/request_ref 输入。

ConnectionOwner 状态建议为 `connecting → initializing → ready → draining → closed`，失败可从任一状态转入关闭。协议核心不要求再套一个进程。不要把每个 DATA chunk 转成一个 Task。

### 4.1 状态归属

连接状态持有：socket 对应的协议状态、effective profile、local/peer settings、待 ACK 的设置批次、发送/接收连接窗口、HPACK encoder/decoder、next stream ID、stream map、连续首部块状态、GOAWAY 边界、有界输出队列与调度器状态。

stream 状态持有：请求引用、两个方向的生命周期、发送/接收窗口、上传 EOF、响应状态和长度校验、有限 body 缓冲、优先级元数据、取消状态与独立 deadline。

运行时 PID、monitor 和 timer reference 由 owner/adapter 管理。便于纯函数属性测试的协议状态不得隐式依赖当前时间或全局配置；时钟和配置作为输入。

### 4.2 写入序列与取消的原子性

只允许一个有序写入通道。读取、处理 WINDOW_UPDATE 和处理取消不能被应用生产者/消费者阻塞；必要时使用每连接一个有界 writer worker，并明确 socket ownership 与异常传播。

HPACK 编码必须在确定发送顺序的提交点进行。取消发生在提交前可以移除请求；提交后不得把已改变共享 HPACK 状态的首部块从队列随意删除。必须保证线上状态连续，或终止无法恢复的连接。

HEADERS 与其 CONTINUATION 构成不可交错的写入单元；必要控制帧也不能插入未完成的首部块。[R1 §4.3] 有界 header-block 限制避免该原子单元无限占用连接。

已被应用放弃的响应首部块，仍需在规范要求的情况下解码，以保持共享 HPACK 状态；不能简单按 stream_id 丢弃所有帧。[R1 §4.3.1]

## 5. WireProfile 契约

### 5.1 配置与运行状态分离

Profile 是有限、可序列化、可验证的数据，不是任意函数回调、原始 socket 指令或无限帧脚本。建议包含以下分组：

| 分组 | 要求 |
|---|---|
| 标识与来源 | schema version、profile ID/revision、来源、目标版本/平台、验证级别 |
| SETTINGS | `[{integer_id, integer_value}, ...]` 有序序列；区分省略字段与显式默认值 |
| 启动 | connection preface 后的合法初始化帧次序；可选连接 WINDOW_UPDATE 与优先级帧 |
| 接收信用 | stream 初始接收窗口、连接目标窗口、阈值/批量补充策略、与内存预算的约束 |
| 首部 | 普通请求伪首部排列、普通首部排序规则、默认字段插入点、重复字段保持策略 |
| HPACK | 字符串 Huffman 策略、索引选择、encoder 表容量策略、敏感字段保护 |
| 优先级 | none / legacy / RFC 9218，及明确的兼容策略；请求类型到优先级元数据的映射 |
| 分帧 | HEADERS/CONTINUATION 分片上限、DATA 分片/合并策略、合法 padding 策略 |
| 限定条件 | 已实现扩展、匹配范围、对端协商后的允许变化、无法复现项 |

不得对 wire 列表做隐式排序、转 map、去重或填入省略的设置。重复 SETTINGS 如被支持必须保留并按序验证其状态变化；尚未支持的 profile 形式明确拒绝，不能偷偷折叠。[R1 §6.5]

既存首部 list 与重复字段保留。自定义 fingerprint 的普通首部顺序必须在**所有默认首部及 body 首部插入之后**形成最终 wire header list。严格模式下，没有明确顺序策略的 map 输入不得被当成保留了用户顺序；可以报错，或者由完整 profile 排序规则确定，必须文档化。

普通请求的伪首部必须合法、唯一并位于普通首部之前；不能为顺序模拟允许重复 `:method` 或非法首部。CONNECT 等不在本次范围的语义不要套用普通 GET 模板。

### 5.2 SETTINGS 和窗口必须真的生效

维护不同方向的 local/peer settings，避免把本地宣告误用为对端发送许可。stream 窗口、连接窗口、HPACK encoder 上限、decoder 上限和 frame receive/send 上限必须分别建模。

连接窗口目标不是 WINDOW_UPDATE increment；启动增量从协议初始连接窗口计算。不允许把较大的 stream 初始窗口直接当成已扩大的连接窗口，也不能生成 0 增量 WINDOW_UPDATE。[R1 §6.9]

Profile 不能宣告当前实现无法承担的能力或内存上限。对端更小的帧/表/流控约束必须遵守，并在观察报告中体现实际行为，不得为了 fixture 一致而违反协商结果。

初始化顺序不可把其他帧放在初始 SETTINGS 之前。SETTINGS ACK 不得人为任意拖延以制造时序；正常协议响应优先于模拟偏好。

### 5.3 首部和 HPACK 策略

支持 Huffman 开关/按长度收益选择、静态表精确索引和名字索引、动态表索引与插入、literal without indexing、never-indexed。保持顺序，不将 HPACK 优化变成首部重排。

Encoder 与 Decoder 都要区分“协商允许的最大容量”和“当前动态表容量”。必须验证表容量缩小再恢复、驱逐、跨请求索引、多个连续 settings 变化后的表尺寸更新，不能继承把两者混为一谈的实现。[R2 §§4,6]

敏感字段默认保护，禁止日志记录 Cookie、Authorization、证书私钥或会话材料。Profile 导入若要求放宽敏感索引规则，必须显式说明风险、要求独立 scope 并获得明确配置；严格安全策略不允许时应拒绝并报告差异，不能默默改变后仍报告精确匹配。

禁止共享跨连接、跨方向、跨身份隔离范围的 HPACK 状态。TLS 会话恢复建立的新 TCP/H2 连接也必须从新的 H2 状态开始。

### 5.4 优先级

支持 legacy PRIORITY/HEADERS priority 字段及现代 `Priority` 首部、HTTP/2 `PRIORITY_UPDATE`。现代/旧模式的协商按 RFC 9218 处理，不能向所有对端无条件同时发送两套信号。[R3]

记录 SETTINGS_NO_RFC7540_PRIORITIES 的连接级约束。验证 PRIORITY_UPDATE 的帧头 stream ID 与 payload 目标 stream ID、方向、目标状态和有界输入。wire weight 字节与配置的语义权重不得混淆。

面向服务器的响应优先级信号，与本地上传 DATA 的公平调度是不同策略。仅发送一个 `Priority` 首部不算完成调度器。首版本地调度使用有界、可测的公平策略；饥饿和控制帧延迟必须有测试。

### 5.5 默认 profile、合成样本与浏览器预置

引入有版本的原生默认 profile，如 `native_v1`，不伪装成浏览器。默认关闭应用层 server push；空 SETTINGS 的历史 wire 行为仅可作为显式兼容 profile/fixture，不能因此保留协议错误。

至少提供两个有明显 wire 差异的自定义测试 profile，覆盖不同 SETTINGS 顺序、初始窗口、伪首部顺序和 HPACK/优先级策略。合成名称必须含 synthetic/test，不以 Chrome/Safari 命名。

真实客户端预置至少具备以下 manifest：产品/版本、OS、采集时间、独立采集工具版本、HTTP 请求场景、h2/h2c、TLS 冷握手/恢复上下文、H2 冷连接/复用状态、已脱敏请求样本、对端设置、raw fixture digest、许可/来源、已匹配字段和已知差异。

`reference-derived`、`synthetic`、`captured-verified` 是不同证据级别。不能使用无版本的 `chrome_latest` 作为稳定契约；也不能把 TLS 模拟器输出误记为真实浏览器采集。

### 5.6 Server push 与扩展能力门槛

默认显式禁用 push。对于必须省略 ENABLE_PUSH 或将其设为 1 的目标 profile，实现有界的 PUSH_PROMISE 解码与拒收流程：保持 HPACK 同步、按规则取消 promised stream，处理在途帧，不向应用暴露推送缓存 API。

禁用生效后的违规 push 应按协议失败，不能一直静默吞掉；初始 settings 生效前后的竞态必须测试。不支持这种处理前，不允许 profile 谎报可以处理 push。

对已注册但尚未实现的扩展，拒绝会宣告能力的设置；未知 wire ID 的观察保留与出站宣告是两个不同概念。注册表快照使用 IANA 来源，不能把当前未知 ID 永久当成任意无副作用值。[R5]

## 6. 连接池与身份隔离

### 6.1 PoolKey

第一版只在同 origin 内复用。PoolKey 至少覆盖：

- scheme/规范化 host/port、实际 h2/h2c 模式；
- 路由或代理路径身份（仅使用项目已经支持的传输路径，不借此新增代理功能）；
- TLS backend、有效安全策略、主机名/SNI/ALPN、客户端证书身份、已解析 TLS profile/能力摘要；
- 完整有效 HTTP/2 profile 的版本化 digest；
- 调用方显式身份隔离范围 `http2_scope`；
- 会改变连接行为、不能安全共享的其他 connect/socket 策略。

Digest 是规范化配置的 digest，不是浏览器名称、Akamai 字符串或带随机 ClientHello 值的每次握手 hash。规范化对象可稳定排列 key，但所有有序 wire 序列必须保持顺序及显式默认值。

同名不同内容 profile 不能复用。修改全局配置仅影响后续解析的新请求，已建立连接继续使用不可变快照。CA/客户端证书文件原路径不变但内容变化时，需要内容身份或显式配置 generation/invalidation，不能只 hash 文件名。

`http2_scope` 是显式的应用身份边界，不靠猜测 Cookie/Authorization 自动识别账户；应用承载多个身份时必须分别指定 scope，默认 scope 的共享范围需写清楚。mTLS 与 TLS 验证策略隔离始终由 PoolKey 强制执行。

不把证书私钥、token、回调内部数据序列化到日志。对于无法稳定比较的自定义 TLS 验证回调/外部配置，应保守地不跨请求复用，或要求显式安全的配置代次。

保留现有 TLS resumption 行为但不得增加跨 profile/scope 的 ticket 共享。审查依赖实际 session cache 语义；不能证明隔离时，拒绝不安全组合或要求调用方明确关闭 resumption，并报告原因；不静默修改选项，更不借用其他身份的会话。

### 6.2 租约、容量和生命周期

池分配的是 **stream reservation**，不是独占整条 socket。并发申请时原子预留容量，避免两个调用者同时看到同一个空位。上限取对端允许值与本地限额的约束；对端降低并发上限后停止接纳新流，不错误终止已存在的合法流。

池有 per-key 和全局连接上限、pending 上限、排队 deadline、空闲回收与 drain deadline。第一个版本可使用每 key 一条连接，达到并发上限后有界排队；额外连接策略需要明确配置，不能无限扩张。

连接握手在池进程外执行。等待同一连接的请求分别可取消；一个等待者超时不应杀掉仍有其他等待者的握手。全部等待者退出后清理无需继续的连接建立任务。

单次请求结束只释放对应 stream/reservation。连接仅在 idle timeout、GOAWAY/drain 完成、不可恢复传输/协议失败或应用停止时关闭。`http2_reuse: false` 创建隔离连接，完成后关闭，便于冷连接采集。

新请求进入 GOAWAY/draining 连接必须被阻止。尚未发送的队列请求可以重新选择可用连接且沿用原 deadline；已经提交的请求不自动重放。

## 7. 请求 API 与协议选择

保持扁平 init 选项，建议增加以下入口。API 名称可在 P0 统一调整一次并记录 ADR，之后测试和文档使用同一契约。

| 选项 | 拟议语义 |
|---|---|
| `http2_profile` | 缺省使用原生 profile；显式指定版本化 ID 或经校验的 WireProfile |
| `http2_reuse` | 默认 true，仅对实际 H2 路径生效；false 为独立连接 |
| `http2_scope` | 稳定、非敏感的调用方隔离标识；缺省是文档化的库默认 scope |
| `http2_priority` | 每请求合法优先级元数据，仅使用 profile 允许的模式；不改连接初始化 |

底层 pool/buffer/capacity 上限通过具名配置管理，不把每条请求的任意对象当成无限池配置。Debug capture 默认关闭，使用单独、显式、受限的观察入口。

新增选项必须贯穿 `FetchOptions → Request.transport_options → 协议选择/PoolKey → owner/core`；字符串 key 与 keyword 的行为一致。不允许未知 `http2_*` 或 profile 内部 key 被静默忽略，也不允许从外部字符串无限创建 atom。

| 请求条件 | 必须保持/新增的行为 |
|---|---|
| 缺省协议 | 仍为 HTTP/1.1，不因本次改造全局改成 `:auto` |
| HTTPS `:auto`，未显式 profile | 保留 h2/HTTP1.1 ALPN 选择；H2 时使用新引擎 |
| HTTPS `:auto`，显式 HTTP/2 profile | 本计划定义为严格要求 H2；未协商 h2 时明确失败，不能静默忽略 profile |
| HTTP `:auto` | 仍为 HTTP/1.1；显式 H2 profile 与此组合报错 |
| HTTP `:h2c` | 复用同一 HTTP/2 核心，直接 prior knowledge；不得 ALPN/Upgrade |
| HTTPS `:http2` | 必须协商 h2；证书/ALPN 错误不能自动退回另一 TLS 实现 |
| 不适用协议 + 新 H2 选项 | 显式报错；不要悄悄降级为没生效的配置 |

保留 `body: stream_pid` 与 `duplex: :half` / `"half"`。不引入未经设计的 `:full` 公共 API；内部必须同时读取响应和发送上传，以处理提前最终响应与流控。

Profile 约束的 User-Agent/普通首部、TLS 配置和 HTTP/2 配置应一致且可诊断，但此次不发明全自动的浏览器身份总控层。现有 TLS profile 的真实字段以锁定依赖为准；缺失 TLS/ALPS 等能力只可标注整体匹配限制，不能伪造其支持。

## 8. 多 stream 正确性与流式 I/O

### 8.1 生命周期、异常与超时

使用合法且不复用的客户端 stream ID，常规从 1 开始递增；首批 priority-only 空闲 stream 引用不等价于已经打开请求。ID 耗尽进入 drain，不回绕。对每个 stream 分别处理状态、响应首部、DATA、trailers、END_STREAM 与长度检查。[R1 §§5,8]

区分 stream error 与 connection error。单次取消、生产者错误、响应长度问题或 deadline 不应直接关闭共享连接。连接级 HPACK/协议错误则终止连接并通知所有受影响请求。

现有 AbortController 以请求适配器接收取消，再定位 queue entry 或 stream；不得把所有调用者指向同一个连接 owner 然后让旧 `:abort` 关闭连接。

分开 request deadline、pool queue deadline、connect/initialization timeout、SETTINGS/PING deadline、socket write-stall timeout、idle/drain timeout。一个 request deadline 不能成为共享连接全局计时器。请求总预算覆盖排队、握手、发送、重定向和响应消费的既有语义，不能每跳重新开始。网络协议已完成并交付为可读 stream 后，不得因为内部请求 Task 结束而丢弃缓冲响应；应用 reader 的 idle/cancellation 与尚在进行的 wire deadline 分别处理。

GOAWAY 的 last_stream_id、错误码及多次 GOAWAY 的收紧边界都要处理。可继续完成的在途请求允许排空；未处理/结果不确定的请求返回结构化结果。默认不自动重放已提交请求，包括非幂等请求与不可回放流式 body。

流式重定向：需要保留 body 的 307/308 等路径不得静默读取已经消费的 PID body 再发一遍；若没有已验证的 replay source 则明确失败。改变方法且丢弃 body 的重定向遵守既有语义，及时停止旧生产者并重新进行连接匹配和敏感信息处理。

### 8.2 有界上传

接入现有 `HTTP.Stream` 生产者确认，维护一个上传 body 的单消费者租约；同一个不可重放 stream 被并发用于两个请求时明确拒绝，不得竞争读取。不使用 `Enum.to_list`、`Enum.join` 或 `IO.iodata_to_binary` 收集整个流式 body。只允许在有读取信用及有界缓冲预算时继续拉取数据。

应用 chunk 与 DATA frame 必须解耦。scheduler 根据 profile、peer frame limit、stream/connection send credit 和 padding 开销决定切分/有限合并；部分发送的尾部留在有限缓冲中。producer chunk 不是可信的无限大小单位。

明确 `max_chunk_bytes` 和 producer/bridge 合同：对过大输入拒绝或在受控入口切片；不能通过保留巨型 binary 的 sub-binary 声称内存已变小。库能保证的是合规 API 内部的有界管道，不是任意外部 PID 无限塞消息时仍无条件有界。

EOF 独立于“暂时无 chunk”；只结束一次。空 body、空 chunk、已知/未知长度都应测试。有 Content-Length 时验证确切字节数；未知长度使用 DATA/END_STREAM，不发送 HTTP/1.1 chunk framing。若既有公共合同拒绝某类 streaming Content-Length，应保持显式拒绝并文档化，不能 silently strip 后误报支持。

收到最终响应不能继续盲目消费上传。确定终止上传时释放 producer/等待中的 ACK，并保留已完成响应；不能在连接级删除其他 stream 的待发送 DATA。半关闭和所需 RST_STREAM 按状态处理。

### 8.3 慢消费者隔离与 receive credit

ConnectionOwner 不得同步调用可能等待应用的 `HTTP.Stream.chunk/3`、Promise.await 或未知 producer。使用有界 BodyBridge/异步信用协议，使慢 stream 只耗尽自己的配额。

分别记账已授予但未接收的连接/stream credit、已解析未交付字节、bridge 中待消费字节和 parser/output 队列。广告窗口与本地预算必须一起验证；不得一边补连接窗口一边把数据无限堆到 bridge。

窗口返还可由“已消费”或“已占用有界缓冲中的可用预算”触发，具体策略由 profile 决定，但始终受总预算约束。避免把一个 stalled stream 的信用耗尽变成对所有健康 stream 的人为永久停顿；若整个连接预算已耗尽，受控全局背压是合理的，必须可观测。

现有非 ACK 手动 reader 模式可能将积压转移到调用者 mailbox。保留旧 API 时明确这一边界；高层消费接口走确认/信用路径。不能把 `read_all` 主动聚合全响应的内存计入“流式管道常量内存”承诺，也不能只测 owner heap 忽略桥接队列和 binary 引用。

监控 producer、body bridge 与真实持有者；Promise 的短生命周期内部 Task 退出不代表用户已放弃响应。外部传入的 stream PID 不得随意 `Process.exit`；优先使用取消/错误协议。一个桥接进程异常不得通过 link 杀掉共享连接。

### 8.4 ex_ssl close/drain 回归

保留已有“TLS peer 已关闭但仍有未消费明文/后续 TLS record”的测试与逻辑意图。先把连接标为不可接纳新请求，再排空可读数据；对实际完成的 streams 成功结算，对没有合法完成标记的 streams 报截断/关闭。

只可对已证明可丢弃的控制写失败执行受限处理；不能把 DATA 写失败、RST_STREAM、截断、取消或超时统一改成成功。共享连接改造后必须重新证明作用范围，不可照搬以全连接 `done?` 为条件的旧单请求捷径。

## 9. 指纹观察、比对与安全

观察器与 profile compiler 解耦，支持分片输入、有界缓冲与明确完成窗口，例如“连接前言至首个请求首部块完成”。不会因为测试端使用本库同一编码器而自动认定正确。

输出至少分为四种来源：`planned`、`serialized`、`transport_send_ok`、`peer_observed`。`send/2` 成功不是对端已收到或同意，更不能作为逐字节实测证明。

观察项包含：有序 SETTINGS（含重复/未知 ID）、初始连接 WINDOW_UPDATE 增量、初始化 PRIORITY、HEADERS 优先级、伪首部/普通首部顺序、HPACK 表示与表变化、分帧、padding、所选 transport/profile/连接实例、首请求或复用请求索引。

提供 Akamai 风格四段投影与结构化 diff，明确投影版本和观察窗口；保留投影未表达的字段。未知/截断/部分观察不能补默认值伪装成完整匹配。[R4]

默认 telemetry 仅记录非敏感概要、计数与资源指标。原始首部块可能包含凭据；raw bytes capture 只能显式启用、限定范围和容量、限定存活时间，默认不写磁盘。fixture 使用专用非真实凭据，禁止提交生产 keylog、cookies、tokens。

观测不得成为热路径的无限 mailbox 或高 cardinality telemetry。更新现有 telemetry 模块，继续使用项目约定的 `[:http_fetch, ...]` 前缀。[S1]

## 10. 分阶段实施与依赖

先做 profile/状态契约与 byte fixtures，再做多路复用 runtime，避免做完池才发现初始化与请求序列化无法分离。每阶段必须有可运行代码与测试，不能最后集中补测。

| 阶段 | 工作包 | 进入下一阶段的 gate |
|---|---|---|
| P0 基线与 ADR | 检查分支、AGENTS、lock、公开 API、已有 h2/ex_ssl 测试；建立基线报告、错误/默认行为矩阵、架构 ADR；明确目标 profile 证据要求 | 能说明现存行为和未运行项；新增测试能揭示当前缺口 |
| P1 Profile 与初始化 | WireProfile/schema/compiler/digest，合法 settings/window/priority 编码，HeaderPolicy，最低限度独立字节观察，冷连接 golden fixtures | 两个合成 profile 在独立端呈现不同且预期的初始化；未知字段不静默忽略 |
| P2 持久协议核心 | Connection/StreamState、local/peer settings、流控、连接级 HPACK、首部原子提交、错误域、push 拒收和优先级状态 | 一个纯连接状态能完成多个及交错 stream；HPACK 冷热序列和取消竞态通过 |
| P3 连接 runtime 与复用 | ConnectionOwner、唯一有序 writer、PoolKey、stream reservation、有界排队、per-request adapter/取消、idle/drain | 实际一条 socket 完成多请求；不同 profile/TLS/scope 隔离；单流取消不伤邻居 |
| P4 背压流式 I/O | 接入现有 PID/Enumerable；上传信用、DATA 调度、提前响应、独立 response bridge 与完整预算 | 慢生产者/消费者下其他流继续前进；内存/队列峰值不随总传输大小增长 |
| P5 指纹验证与预置 | 观察/摘要/diff 完整化；真实样本 manifest/import；legacy/RFC9218、复用 HPACK、TLS/H2 一致性报告 | profile→实际字节闭环；浏览器证据分级；不靠首包 GET 或摘要相等冒充完整匹配 |
| P6 集成与交付 | flat options、所有后端协议矩阵、回归/互操作/故障测试、压力报告、docs、包消费 CI、迁移说明 | 验收矩阵全部明确通过/失败/未验证；没有性能数字或样本来源造假 |

P1 的有序字节观察不可推迟到 P5 才开始；P5 是扩展与目标样本校准。P2 可先用纯 state 测试，P3 再接真实 socket。P4 之后统一验证 fingerprint 未因公平调度/分帧重构被破坏。

## 11. 验收矩阵

每项在实现报告中关联测试路径、执行命令和结果。正常协议和异常路径都要覆盖；随机属性测试记录 seed。

| ID | 必须验证的行为 |
|---|---|
| F01 | 有序 SETTINGS、省略/显式默认值、未知 ID 观察及 profile 错误处理 |
| F02 | 初始 WINDOW_UPDATE 的增量正确；本地/对端 settings 与连接/stream 窗口互不混淆 |
| F03 | 伪首部和普通首部顺序、重复字段、默认 UA/body 首部插入位置真实生效 |
| F04 | legacy priority、HEADERS priority、RFC9218 协商/PRIORITY_UPDATE 与本地调度分别有测试 |
| F05 | Huffman、静态/动态索引、never-index、容量缩小到 0 再恢复；第二/第三请求可被独立 HPACK 解码 |
| F06 | 观察器接收任意分片、截断、超限和未知字段；报告来源与不完整状态，默认脱敏 |
| C01 | 两次顺序请求：服务器只 accept 一次；连接前言只一次；stream ID 正确推进 |
| C02 | 至少 3 个真正重叠 stream 在一条连接上交错响应，不以顺序执行冒充多路复用 |
| C03 | 相同 profile 名但不同内容、不同 TLS backend/安全策略/mTLS/scope 均不错误复用 |
| C04 | 并发申请的容量原子预留；对端降低并发上限；有界排队及单等待者超时 |
| C05 | 请求完成保留连接；idle 回收、应用关闭、ID 耗尽与 GOAWAY drain 可释放全部资源 |
| C06 | SETTINGS/PING/RST/WINDOW_UPDATE 处理按错误域执行；取消/失败不污染相邻 stream |
| U01 | 大型增量上传远超初始窗口；窗口归零暂停，更新后恢复，不能预读整个 body |
| U02 | 独立连接信用/stream 信用、settings 造成负发送窗口、padding 计费与溢出处理 |
| U03 | 一个上传生产者停顿/退出时，另一个健康请求仍完成；待 ACK 不遗留 |
| U04 | 空 body/空 chunk/EOF、已知或显式拒绝的 streaming Content-Length、未知长度不发 H1 chunk framing |
| U05 | 提前 4xx/完成响应终止上传；已返回成功响应不被无关控制写失败覆盖 |
| R01 | 慢消费者不阻塞 connection owner；缓冲/信用有界且健康流可前进 |
| R02 | 响应 stream 在 Promise 内部 Task 结束后仍可读取；reader/bridge 异常不会杀连接 |
| E01 | HEADERS 编码提交前后取消；CONTINUATION 不能插帧；已放弃流的 HPACK 更新仍正确 |
| E02 | GOAWAY last_stream_id、多个 GOAWAY、REFUSED_STREAM、连接断开不自动重放已发请求 |
| E03 | 流式 307/308 不重用耗尽 body；敏感头与 mTLS 重定向约束不回归 |
| E04 | peer close 后跨 TLS record 的明文排空；END_STREAM 缺失仍报截断；正常完成 streams 不受邻居未完成影响 |
| E05 | 巨大首部、解压膨胀、续帧洪泛、无效状态/字段、控制帧风暴均受限 |
| E06 | push 允许/省略/禁用生效竞态；拒收 push 后后续请求 HPACK 正确 |
| M01 | cleartext h2c、OTP :ssl h2、ex_ssl h2 全部测试；TLS 验证失败 fail-closed |
| M02 | HTTPS :auto 既有降级只在未显式 profile 时保留；不适用配置和拼写错误明确报错 |
| M03 | HTTP/1.1、Promise/Response、SSE/WebSocket、HTTP/3/WebTransport 现有测试无回归 |
| V01 | 至少一个独立 H2 实现的服务端互操作，fixture 不完全来自本库 codec |
| V02 | 原生与两个合成 profile 冷/热/并发观察；真实浏览器 profile 单独给出来源与匹配范围 |
| V03 | 长时间连接 churn 与大小不同的流式载荷：监控进程/队列/保留 binary，不只统计吞吐 |

独立端可选维护中的 nghttp2 或其他成熟 H2 实现，固定版本/镜像 digest 并记录来源；它只能作为测试依赖，不替代生产协议引擎。浏览器采集不是访问一个网页打印 hash 就完成，需要本地可重复场景与原始证据。

## 12. 测试执行与报告

依照仓库现有工具和 CI；以下命令来自根目录运行。[S1]

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

补充按路径运行所有受共享模块影响的 app 测试和已有 E2E/packaged-consumer smoke checks。先检查实际 aliases/workflows；不得将不存在的命令描述为已执行。环境缺少工具或网络时保留真实错误，区分 code failure 与 environment failure。

性能报告仅给实测：硬件/OTP/Elixir/TLS 后端、连接数、stream 并发、服务端限额、payload、吞吐/延迟与缓冲峰值。与旧单连接单请求基线对比，避免将协议可复用直接等同于固定倍数提速。

## 13. 文档与提交交付物

代码和测试之外，至少维护：

| 文件 | 内容 |
|---|---|
| `docs/HTTP2_IMPLEMENTATION_PLAN.md` | 本计划与实施状态；不回写虚构已通过项 |
| `docs/HTTP2_ARCHITECTURE.md` | 状态归属、owner/pool/bridge、生命周期、窗口和 HPACK 提交边界 |
| `docs/HTTP2_FINGERPRINTS.md` | Profile schema、排序/默认值/能力校验、优先级、TLS 配合、观测来源 |
| `docs/HTTP2_PROFILE_CAPTURE.md` | 独立采集、脱敏、manifest、冷/热连接比对和证据级别 |
| `docs/HTTP2_IMPLEMENTATION_REPORT.md` | 基线 SHA、每阶段实现、测试矩阵、运行日志摘要、限制与未验证项 |
| README / CHANGELOG | 实际可用 API、默认行为、迁移方式与局限；不自动 bump/publish |

按 P0–P6 做可审阅的本地 conventional commits（遵守当前环境权限）；不自动 push/merge/tag/release。每阶段交付代码、测试和状态记录。禁止仅生成文档、stub、永远跳过的测试或新的 unsupported 返回值后宣称完成。

## 14. 关键拒绝条件

以下任一情况存在，都不能宣布本次升级完成：

- profile 只改变配置对象，不改变实际出站字节；或摘要相同就报告完整模拟成功；
- PoolKey 只按 host 或 profile 名称匹配，未隔离 TLS/安全身份；
- HTTP/2 仍每请求一条连接，或一条连接只能顺序处理请求；
- 每 stream 独立 HPACK，或取消导致共享压缩状态错位；
- streaming body 被整体聚合，或慢消费者让共享 owner 同步等待；
- 一个请求超时/取消就关闭整条健康连接，或默认重放已发送 body；
- 支持新 profile 的代价是关闭证书验证、忽略协议错误或虚假宣告能力；
- 浏览器预置使用猜测版本/数值、没有样本来源，或把未跑的互操作测试写成通过。

## 15. 来源与复核入口

源码以基线提交固定，避免 main 变化造成结论漂移。以下 URL 是实施人员的复核入口；协议要求以对应 RFC、已采纳勘误和注册表为准，本文的模块拆分、阶段与运行策略是本项目的设计决策。

- [S1] 根目录 AGENTS：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/AGENTS.md`
- [S2] 协议核心：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_core/lib/http/http2.ex`
- [S3] HPACK：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_core/lib/http/http2/hpack.ex`
- [S4] SocketClient：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_fetch/lib/http/socket_client.ex`
- [S5] Stream：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_fetch/lib/http/stream.ex`
- [S6] FetchOptions：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_fetch/lib/http/fetch_options.ex`
- [S7] ExSSL transport：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_core/lib/http/transport/ex_ssl.ex`
- [S8] HTTP/2 集成回归：`https://github.com/gsmlg-dev/http_fetch/blob/b4ad2f5ef003415941b97f5e0cc78c21dcc94296/apps/http_fetch/test/http/socket_client_http2_test.exs`
- [R1] RFC 9113，重点 §§3–6、8–10：`https://www.rfc-editor.org/rfc/rfc9113.html`
- [R2] RFC 7541，重点 §§4–7 和 Appendix C：`https://www.rfc-editor.org/rfc/rfc7541.html`
- [R3] RFC 9218，重点 §§4、5、7、9：`https://www.rfc-editor.org/rfc/rfc9218.html`
- [R4] curl_cffi 官方 HTTP/2 指纹字段说明，仅作摘要格式参考：`https://curl-cffi.readthedocs.io/en/latest/impersonate/customize.html`
- [R5] IANA HTTP/2 Parameters：`https://www.iana.org/assignments/http2-parameters`
