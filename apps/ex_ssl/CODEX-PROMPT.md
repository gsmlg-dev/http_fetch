# Codex 任务：为 ex_quic 抽出 ex_ssl 的 TLS 1.3 握手接口

在 `gsmlg-dev/ex_ssl` 中直接实施改造，交付代码、测试和文档。不要只提交设计文档、delegate 包装、模拟握手或 TODO 接口。

## 1. 目标与范围

后续 `ex_quic` 将用 Elixir 实现 QUIC，支持 JA3/JA4 指纹识别与 profile 驱动的模拟，并集成到 `:abyss` UDP 服务器。本任务为它提供真正可驱动的 TLS 1.3 安全引擎。

依赖方向固定为 `abyss → ex_quic → ex_ssl → OTP crypto/public_key`。只修改 `ex_ssl`；不添加对 `ex_quic`、`:quic`、Abyss 的运行时依赖，不修改其他仓库。开发/测试辅助程序可以使用独立实现。

必须实现无 TLS record、无 socket 的客户端及服务端完整证书握手，并导出有明确加密级别、方向和时序的 traffic secret。仅导出 cipher suite 列表或内部函数不算完成。

不在本仓库实现 UDP 监听、QUIC 包/frame、Initial secrets、header protection、ACK、重传、stream、拥塞控制、HTTP/3 或 Abyss dispatcher。服务端握手引擎不等于新增 `SSL.listen`/`SSL.transport_accept` 等 TCP 服务端 API。

首期完成完整 1-RTT 证书握手；QUIC 0-RTT、会话恢复、服务端 mTLS 可以明确暂不提供，但不能删除或破坏现有 TCP 路径的相关能力。能力矩阵必须按角色和传输模式描述，不能用一个笼统的 `supported: true` 代替。

## 2. 先核对当前实现，再进行小步重构

阅读 `AGENTS.md`、架构、设计、兼容性文档和相关测试，记录工作分支及 HEAD，先运行基线测试。保留用户未提交的改动，不自动发布、推送或升级版本。

设计审查快照为 `bcb946d40327c68f238df5fd66d945d90f251af4`，仅供定位，不能强制回退到它。该快照中：

- `lib/ssl/protocol/handshake_machine.ex` 的 `SSL.Protocol.HandshakeMachine` 是按完整 TLS record 推进的客户端协调器，并包含 TLS 1.2 分支。
- `lib/ssl/crypto/key_schedule.ex` 已有 handshake/application traffic secret 派生，但 `traffic_state/2`、`traffic_update/2` 属于 TLS record 路径。
- `lib/ssl/capabilities.ex` 已有 TLS 1.3 suite、group 和 signature 能力信息。
- `lib/ssl/client_hello/wire_profile.ex` 已提供有序 profile，默认有 TCP 用的 session ID/record 策略。

核对这些模块的当前调用方，并检查 HandshakeFramer、Transcript、ServerFlightVerifier、ClientHello parser/materializer/serializer、PKIX 和现有指纹实现。复用已有正确实现，不创建另一份 TLS 客户端状态机、密码表或 JA3/JA4 算法副本。

规范基线遵循仓库的 RFC 9846，并结合 RFC 9001 的 QUIC/TLS 集成约束；RFC 8446 和 RFC 8448 仅在历史说明/适用测试向量中引用。核对相关勘误。现有文档若写着 client-only 或 QUIC 不在范围内，只做本次接口及服务端安全引擎所需的局部修订，记录 ADR；不要把本次任务扩成完整 QUIC/TCP server 产品。

## 3. 架构：共享握手核心，加两个适配入口

目标分层：

`现有 SSL/TCP API → 现有运行时与 record 适配 → 共享 TLS 1.3 握手核心`

`新增 SSL.QUIC API → QUIC 模式适配 → 同一个 TLS 1.3 握手核心`

共享核心负责握手消息、transcript、协商、认证、Finished 和 TLS secret 派生；不读写 socket，不处理 TLS record 加解密，不启动进程、定时器或调用 Logger。使用不可变状态、小函数和显式动作；禁止为每条握手消息创建进程。

时钟、配置加载和随机材料获取放到可测试边界；生产使用安全随机与每连接新鲜的临时密钥。不得为了“纯函数”改用可预测随机，也不能每次 feed 都重新生成同一握手的材料。

将 TLS 1.3 的 TCP 路径真实接到共享核心，再由 record 适配层处理封装、CCS、序列号和 TLS record key update。TLS 1.2 分支保留原有职责。不得将裸握手临时包装成伪 TLS record 再调用旧状态机；也不得保留两套长期分叉的 TLS 1.3 实现。

不使用运行时 OTP `:ssl` 或原生 TLS 库替代握手。`:ssl` 仅用于测试与现有 TCP 行为对照；密码运算和证书验证继续使用 OTP `:crypto`、`:public_key` 及项目已有 PKIX 逻辑。

## 4. 新增稳定公共入口 SSL.QUIC

以 `SSL.QUIC` 为公开入口，内部模块继续使用 `SSL.*`。先定义 typespec、返回值、状态所有权和动作顺序，再实现。以下函数名是建议，允许依据仓库惯例微调，但语义必须完整：

`capabilities/0`：查询本实现实际可用的 TLS 1.3 能力及限制。
`new/2`：按 `:client` / `:server` 初始化，返回状态和初始有序动作。
`feed/3`：输入状态、加密级别、握手字节，返回新状态和有序动作。
`info/1`：只返回脱敏后的协商/认证状态。
`abort/2`：终止实例并解除不再需要的敏感数据引用。

这些是状态机 API，不是 socket API。调用者持有唯一的当前状态，不依赖全局 Registry、ETS 或一个隐藏的 `SSL.Connection` 进程。

### 输入边界

输入是握手消息编码（包含 handshake type 和 uint24 长度），不含 TLS record header、QUIC packet 或 CRYPTO offset。调用者在每个加密级别内完成重组、去重并只交付新的连续字节；TLS 接口负责连续字节中的消息分片/合并与有限缓冲。不能要求一次 feed 恰好一个完整握手消息。

明确合法的当前接收级别，并为未来级别的外部缓存提供可用状态信息。禁止跨加密级别拼接同一握手消息。API 不负责 QUIC 的乱序缓存、重传、发送 ACK 或网络超时。

配置需支持角色、已加载证书/私钥、信任与身份验证策略、与 SNI 分离的 reference identity、ALPN、profile、本端 transport parameter 原始字节及资源上限。服务端身份验证不能仅依赖 SNI，关闭 SNI 也不能自动关闭主机名/IP 验证。

### 输出边界

返回一个具有明确总顺序的 action 列表，至少表达：

- 输出某加密级别的握手字节；
- 安装某加密级别、`read` 或 `write` 方向的 secret，并携带 suite/AEAD/HKDF 信息；
- 对端 transport parameters 与其认证状态；
- 协商 ALPN、证书认证结果及握手完成；
- 结构化 TLS alert、API 配置错误或交给 QUIC 层处理的协议错误。

安装所需 write secret 的动作必须先于对应级别的输出字节。不能把 keys、bytes、events 放在互不关联的队列后由调用者猜顺序。明确方向始终相对于当前端点，分别测试客户端及服务端。

严格区分 secret 已可用、对端已认证、TLS 握手完成和 QUIC 握手确认；应用 secret 可用不等于上述状态全部成立。`SSL.QUIC` 不能声称发出/收到 HANDSHAKE_DONE，也不负责 QUIC 的握手确认或旧包密钥丢弃。

定义 action 交付语义：返回的字节视为提交给调用者的可靠发送队列，不是已经发到网络或收到 ACK。调用者重传时使用原字节，不能再次驱动 TLS 来“生成重传”。终态、空输入及重复调用不能重新导出 secret 或重新发出完成事件。

## 5. QUIC 模式与密钥职责

QUIC 模式限定 TLS 1.3；ClientHello 使用空的 legacy_session_id，禁用 middlebox compatibility、record shaping 及 CCS。握手字节按 Initial/Handshake/Application 级别输出，不走 TLS record 层，也不输出 EndOfEarlyData 或 TLS KeyUpdate。非法输入与错误级别必须有确定的错误归属和测试。

支持 `quic_transport_parameters`（0x0039）在 ClientHello 和 EncryptedExtensions 中传递。`ex_ssl` 校验扩展长度、重复、所在消息及必须出现的约束，保留原始字节与顺序；参数条目的编解码、重复参数 ID、CID/流控等 QUIC 语义由 `ex_quic` 负责。普通 TCP 模式不能意外发出 QUIC transport parameters。不得将缺失扩展和“扩展存在但 payload 为空”合并成一个状态。

允许上层早期取得对端参数用于协议处理，但要明确此时未认证；成功状态需经过握手验证。未实现 PSK/0-RTT 时不得使用它们或签发误导性的能力声明；对端合法地提供但服务端不选择的可选能力，应按规范处理，不要一律当畸形输入。

TLS handshake/application traffic secrets 由 `ex_ssl` 提供；QUIC Initial 派生、packet/header protection、版本特定 labels 和 key update 由 `ex_quic` 实现。本任务不导出 TLS `TrafficState` 作为 QUIC packet state，不把 `traffic_state/2` 或 `traffic_update/2` 用在 QUIC 上。

能力查询复用单一注册表，区分“已实现”“当前 OTP crypto 可用”和“当前配置允许”。TLS 1.3 suite 的 AEAD/hash/key length 与 group/signature 能力分别描述；至少覆盖现有 0x1301/0x1302/0x1303 中环境可用的组合，并逐项测试。QUIC header-protection 原语是否可用，留给 `ex_quic` 做最终能力交集，不能把 TLS 能力查询宣称为完整 QUIC 能力证明。

不得用 TLS exporter API 代替 traffic-secret 交付，也不得公开 master secret、私钥和全部中间状态。敏感 state/action 的 Inspect、异常、日志和 telemetry 默认脱敏；对外 info 不含密钥。只向握手驱动者交付必要 traffic secret，消费后避免长期重复保存；失败/终止后释放引用，但不要宣称 BEAM 提供可靠内存清零。

## 6. 必须实现真实客户端与服务端握手

客户端需完成带证书链和主机名/IP 验证的握手，保留已有认证与 client identity 行为。服务端需执行真正的参数协商、临时密钥交换、证书发送、CertificateVerify 签名、Finished 生成与验证，不得用 role 参数、固定响应或关闭验证冒充支持。

复用 transcript/签名/密钥派生基础；补齐服务端所需行为。HelloRetryRequest 包括客户端处理和服务端生成，覆盖 message_hash 重写、第二次 ClientHello 约束及非法重复 HRR。TLS HRR 与 QUIC Retry 是不同机制，本仓库不处理 QUIC Retry。

保持 exact-wire transcript：发送侧使用最终实际输出的握手字节；接收侧使用原始握手字节，不能解析后重新序列化再计算 transcript。身份策略、CertificateVerify 和 Finished 失败必须阻止成功状态。基础服务端未要求客户端证书时，不得把完成的握手标为“已认证客户端身份”。

对暂不实现的 server mTLS/resumption/0-RTT，区分不支持的本地请求与合法但未被选择的对端提议，并返回/记录真实状态。握手完成后合法的 NewSessionTicket 必须能按明确策略有界解析并处理或忽略；不能仅因为本地不存票据就无条件中断有效连接。禁止使用 QUIC 模式的 TLS KeyUpdate/post-handshake authentication 绕过能力限制。

## 7. 指纹识别与模拟所需接口

复用现有 ClientHello parser/materializer/serializer/WireProfile 和已实现的指纹逻辑，补齐直接处理裸 ClientHello 握手字节的公共入口。调用者不需要 TLS record 或 socket，也不需要先完成认证握手。

将“观察解析”和“可发起握手的 profile 校验”分开：观察器要保留未知扩展和未支持算法的原始 ID/有序特征；不能因本库无法协商该算法而丢掉整个合法 ClientHello。用于实际连接的 profile 则只能使用有实现支撑、符合协议的能力；GREASE 与安全可忽略的扩展按规范处理。

分析接口由调用者显式提供 `:tcp` / `:quic` 传输上下文，不从 ALPN 猜测。JA4 的 QUIC 输出使用 q 前缀；JA3 输出保留原始投影串及 hash，并标注 QUIC 来源。按官方定义处理 GREASE、排序和 signature_algorithms 顺序，不能把 JA4 的排序用于实际序列化。

指纹、对端 ClientHello 元数据与证书认证状态分开。不能把指纹相同解释为客户端身份相同或完全复刻浏览器，也不能用指纹代替认证。若支持记录可观察的 ECH 外层内容，必须注明来源，不能声称获取不可见的内层 ClientHello。

模拟流程必须是 profile → 新鲜材料 → 最终握手字节 → 从这些字节计算指纹。禁止配置一个目标哈希后直接作为计算结果返回，禁止为匹配指纹跳过安全校验或复用真实临时密钥。QUIC profile 使用独立合法默认值；对明确不适用的 TCP record 配置返回错误，不要默默忽略用户显式选项。

保留扩展/cipher/group 的有序结构与原始字段。规范化和哈希只发生在分析层，不得变更握手 transcript。选定官方测试向量/固定版本的独立参考工具，并记录来源与许可，不凭空命名“某浏览器完全一致”profile。

## 8. 测试与验收

新增不依赖 socket 的握手驱动测试：以真实测试证书、实际 ECDHE/签名/Finished 在 client 与 server 间搬运带级别的字节，验证双方 read/write secrets 成对一致及总动作顺序。自连接测试是必要条件，不是独立互操作的替代。

测试至少分为以下几组，针对每组给出实际命令和结果：

A. 基线回归：现有 TLS 1.2/1.3 TCP、STARTTLS、ALPN/SNI、PKIX、已有 mTLS/resumption、active/passive 和错误语义保持原有支持范围；确定性 fixture/profile 的输出不意外变化。修复新增退化，不删除失败测试或降低安全断言。

B. 分片与边界：单字节输入、header/body 分裂、同级多消息合并、错误级别、跨级半消息、未知类型、声明超长、certificate/extension/握手累计限制、失败后继续输入、空输入和无进展循环。不要把 TLS record header 当成裸握手接受；所有资源上限可测试，不能照 uint24 声明长度无限分配。

C. 握手与认证：普通双端握手、HRR、无共同 suite/group/ALPN、不支持或未提议的选择、无效证书链、身份不符、CertificateVerify/Finished 篡改。mTLS 等测试仅按真实支持矩阵声明；验证关闭 SNI 不会绕过身份校验。

D. 边界契约：secret 方向/级别/次数、输出次序、未认证参数与认证完成区别、Initial 与 packet 密钥不由本接口产生、TLS alerts 不包装为 record、失败后脱敏。测试无需启动 SSL.Connection/socket 或运行时 :ssl。

E. 指纹：官方/独立参考 fixture、一致的 raw 与 hash、q/t 区分、GREASE、未知值、有序序列化、分片不影响结果，以及实际 emitted ClientHello 而非另一份模板的指纹一致性。

F. 外部验证：增加可复现的测试专用 QUIC-TLS 对照 harness，选择有裸握手接口的独立实现（如 BoringSSL QUIC hooks 或合适的 aioquic TLS 接口），分别覆盖本实现客户端与服务端，至少验证真实握手成功及 secrets/协商结果。固定版本和证书配置；外部工具只作测试依赖。不得为此在 ex_ssl 中开发完整 QUIC 栈。

RFC 8448 的适用向量用于独立检查 transcript、HKDF、CertificateVerify/Finished 等，不把其中完整 TCP records 直接当作 QUIC 输入。既有 OTP :ssl/OpenSSL TCP 测试继续保留，但不能将 TCP 成功描述为 QUIC-TLS 对照已通过。

默认测试离线可运行；另提供明确的独立实现测试命令/CI job。缺少环境时标记 blocked/skipped，给出可复现步骤，不把未运行当通过。报告明确区分：单元/向量、自连接、独立 QUIC-TLS 对照、完整 QUIC 网络互通；最后一项不属于本次仓库任务。

## 9. 交付与执行顺序

按可审查的小步推进：先保存基线和定义公共契约，再抽共享核心并接回 TCP，然后实现 SSL.QUIC 客户端/服务端、指纹公共入口、边界测试和独立对照。

交付实际代码及测试，同时更新 README、AGENTS、架构/兼容性文档、CHANGELOG，并新增或按仓库惯例命名：

- `docs/QUIC_TLS_INTERFACE.md`：配置、输入责任、完整动作顺序、认证/secret 生命周期、transport parameter 边界、错误、纯状态机驱动示例。
- `docs/QUIC_TLS_IMPLEMENTATION.md`：角色/传输模式能力矩阵、已完成范围、验证命令、真实结果和剩余问题。

示例不硬编码 h3 为产品默认，也不暗示完成 HTTP/3；使用显式配置或测试 ALPN。文档与代码注释沿用仓库的英文风格。

运行仓库现有质量检查，至少包含 `mix format --check-formatted`、`mix compile --warnings-as-errors` 和 `mix test`；其他检查按项目现有配置执行。记录基线失败与本次新增失败的区别。

最终报告列出改动文件、公共 API、两种角色的真实能力、执行过的测试/未执行原因，以及 ex_quic 可使用的接口。若未完成关键项，明确剩余工作，绝不能标记为完成或生产安全就绪；不要停留在“还需要研究”的结论，直接完成可执行的实现。

本任务完成的含义：ex_quic 可以仅通过有文档的公共接口、在自己持有的状态中驱动实际 TLS 1.3 双端握手、取得必要 secrets 和指纹材料，而不依赖 TLS record、SSL socket 或 SSL.Protocol.* 私有结构。

## 参考来源

- 审查快照：https://github.com/gsmlg-dev/ex_ssl/tree/bcb946d40327c68f238df5fd66d945d90f251af4
- TLS 1.3 规范（RFC 9846）：https://www.rfc-editor.org/info/rfc9846/
- QUIC/TLS（RFC 9001，重点第 4、6、8 节）：https://www.rfc-editor.org/rfc/rfc9001.html
- 历史握手测试向量（RFC 8448）：https://www.rfc-editor.org/rfc/rfc8448.html
- BoringSSL SSL_QUIC_METHOD 公共契约：https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/ssl.h
- JA4 技术定义：https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- JA3 定义：https://github.com/salesforce/ja3

外部 HEAD/main 链接仅供定位；引入 fixture、对照工具或文档快照时须固定具体版本并记录许可。
