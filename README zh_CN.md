# 多方阈值签名方案
[![MIT licensed][1]][2] [![GoDoc][3]][4] [![Go Report Card][5]][6]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE
[3]: https://godoc.org/github.com/bnb-chain/tss-lib?status.svg
[4]: https://godoc.org/github.com/bnb-chain/tss-lib
[5]: https://goreportcard.com/badge/github.com/bnb-chain/tss-lib
[6]: https://goreportcard.com/report/github.com/bnb-chain/tss-lib

采用宽松的 MIT 许可证。

注意！这是一个供开发人员使用的库。你可以在 [这里](https://docs.binance.org/tss.html) 找到一个可用于币安链 CLI 的 TSS 工具。

## 介绍
这是基于 Gennaro 和 Goldfeder CCS 2018 [1] 的多方 {t,n}-阈值 ECDSA（椭圆曲线数字签名算法）的实现，以及采用类似方法的 EdDSA（Edwards 曲线数字签名算法）。

该库包括三个协议：

* 密钥生成用于创建无可信经销商的秘密共享（"keygen"）。
* 签名用于使用秘密共享来生成签名（"signing"）。
* 动态组用于在保持秘密的同时更改参与者组（"resharing"）。

⚠️ 不要错过 [这些重要说明](#如何安全地使用此库) 关于如何安全地实现此库

## 理由
ECDSA 被广泛用于加密货币，例如 Bitcoin、Ethereum（secp256k1 曲线）、NEO（NIST P-256 曲线）等。

EdDSA 被广泛用于加密货币，例如 Cardano、Aeternity、Stellar Lumens 等。

对于这些货币，该技术可用于创建加密钱包，其中多个方必须合作来签署交易。请参见 [多签用例](https://en.bitcoin.it/wiki/Multisignature#Multisignature_Applications)

每个参与者在本地存储每个密钥/地址的一个秘密共享，协议将其保持安全——它们在任何时候都不会被透露给他人。此外，没有可信的共享经销商。

与 MultiSig 解决方案相比，TSS 生成的交易通过不透露哪些 `t+1` 参与者参与签名来保护签署者的隐私。

还有一个性能优势，即区块链节点可以检查签名的有效性，而无需任何额外的 MultiSig 逻辑或处理。

## 使用
你应该首先创建一个 `LocalParty` 的实例，并为其提供所需的参数。

根据你想要做的事情（keygen、signing 或 resharing），你使用的 `LocalParty` 应该来自相应的包。

### 设置
// 使用 keygen party 时，建议事先预计算"安全素数"和 Paillier 秘密，因为这可能需要一些时间。
// 此代码将使用并发限制生成这些参数，该限制等于可用 CPU 核心数。
preParams, _ := keygen.GeneratePreParams(1 * time.Minute)

// 为网络上的每个参与对等方创建一个 `*PartyID`（你应该为每个对等方调用 `tss.NewPartyID`）
parties := tss.SortPartyIDs(getParticipantPartyIDs())

// 设置参数
// 注意：`id` 和 `moniker` 字段是为了方便你轻松追踪参与者。
// `id` 应该是代表此方在网络中的唯一字符串，`moniker` 可以是任何东西（甚至留空）。
// `uniqueKey` 是此对等方的唯一标识密钥（例如其 p2p 公钥）作为 big.Int。
thisParty := tss.NewPartyID(id, moniker, uniqueKey)
ctx := tss.NewPeerContext(parties)

// 选择一条椭圆曲线
// 使用 ECDSA
curve := tss.S256()
// 或使用 EdDSA
// curve := tss.Edwards()

params := tss.NewParameters(curve, ctx, thisParty, len(parties), threshold)

// 你应该保持 `id` 字符串到 `*PartyID` 实例的本地映射，以便传入的消息可以恢复其原始方的 `*PartyID` 以传递给 `UpdateFromBytes`（见下文）
partyIDMap := make(map[string]*PartyID)
for _, id := range parties {
    partyIDMap[id.Id] = id
}### 密钥生成
为密钥生成协议使用 `keygen.LocalParty`。当协议完成时，你通过 `endCh` 接收的保存数据应该被持久化到安全存储中。

party := keygen.NewLocalParty(params, outCh, endCh, preParams) // 省略最后一个参数以在第 1 轮中计算预参数
go func() {
    err := party.Start()
    // 处理错误 ...
}()### 签名
为签名使用 `signing.LocalParty`，并为其提供要签名的 `message`。它需要从密钥生成协议获得的密钥数据。签名将在完成后通过 `endCh` 发送。

请注意，签署消息需要 `t+1` 个签署者，为了获得最佳使用效果，不应涉及超过这个数量。每个签署者应该对谁是 `t+1` 签署者有相同的看法。

party := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // 处理错误 ...
}()### 重新共享
使用 `resharing.LocalParty` 重新分配秘密共享。通过 `endCh` 接收的保存数据应该覆盖存储中现有的密钥数据，或者如果该方正在接收新共享，则写入新数据。

请注意，`ReSharingParameters` 用于为此 Party 提供更多关于应进行的重新共享的上下文。

party := resharing.NewLocalParty(params, ourKeyData, outCh, endCh)
go func() {
    err := party.Start()
    // 处理错误 ...
}()⚠️ 在重新共享期间，密钥数据可能在轮次中被修改。在从 `end` 通道接收到最终结构之前，不要覆盖保存在磁盘上的任何数据。

## 消息传递
在这些示例中，`outCh` 将收集来自该方的传出消息，`endCh` 将在协议完成时接收保存数据或签名。

在协议期间，你应该为该方提供从网络上其他参与方接收的更新。

一个 `Party` 有两个线程安全的方法用于接收更新。
// 从网络更新方状态时的主要入口点
UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (ok bool, err *tss.Error)
// 当在本地运行或测试时，你可以使用此入口点来更新方的状态
Update(msg tss.ParsedMessage) (ok bool, err *tss.Error)一个 `tss.Message` 有以下两个方法用于将消息转换为网络数据：
// 返回编码的消息字节以通过网络发送，以及路由信息
WireBytes() ([]byte, *tss.MessageRouting, error)
// 返回 protobuf 包装器消息结构，仅在某些特殊情况下使用（即移动应用）
WireMsg() *tss.MessageWrapper在典型的用例中，预计传输实现将通过本地 `Party` 的 `out` 通道消费消息字节，将它们发送到 `msg.GetTo()` 结果中指定的目标，并在接收端将它们传递给 `UpdateFromBytes`。

这样就不需要处理 Marshal/Unmarshalling Protocol Buffers 来实现传输。

## ECDSA v2.0 中预参数的更改

版本 2.0 中添加了两个字段 PaillierSK.P 和 PaillierSK.Q。它们用于生成 Paillier 密钥证明。从 2.0 之前的版本生成的密钥值需要重新生成（resharing）密钥值以用必要的字段填充预参数。

## 如何安全地使用此库

⚠️ 本节很重要。请务必阅读！

消息传输的实现由应用层决定，此库不提供。以下每个段落都应仔细阅读并遵循，因为实现安全的传输对于确保协议的安全性至关重要。

在构建传输时，它应该提供广播通道以及连接每对方的点对点通道。你的传输还应该在方之间采用合适的端到端加密（推荐使用带有 [AEAD 密码](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) 的 TLS），以确保一个方只能读取发送给它的消息。

在你的传输中，每条消息应该用一个 **会话 ID** 包装，该 ID 对单个 keygen、signing 或 re-sharing 轮次的运行是唯一的。此会话 ID 应该在带外商定，并且在轮次开始前仅由参与各方知道。收到任何消息时，你的程序应确保接收到的会话 ID 与开始时商定的相匹配。

此外，你的传输中应该有一个机制来允许"可靠广播"，即方可以向其他方广播消息，使得每个方都保证接收相同的消息。网络上有几个这样做的算法示例，通过共享和比较接收到的消息的哈希值。

超时和错误应由你的应用程序处理。可以在 `Party` 上调用 `WaitingFor` 方法来获取它仍在等待消息的其他方的集合。你也可以从 `*tss.Error` 中获取引发错误的罪魁祸首方的集合。

## 安全审计
Kudelski Security 进行了对该库的全面审查，其最终报告在 2019 年 10 月发布。该报告的副本 [`audit-binance-tss-lib-final-20191018.pdf`](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf) 可在本仓库的 v1.0.0 发行版本说明中找到。

## 参考文献
\[1\] https://eprint.iacr.org/2019/114.pdf