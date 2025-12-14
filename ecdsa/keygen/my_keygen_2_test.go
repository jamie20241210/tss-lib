// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa" // 标准库：ECDSA 数字签名算法
	"encoding/json"
	"math/big" // 标准库：大整数运算
	"testing"  // 标准库：单元测试框架

	"github.com/bnb-chain/tss-lib/v2/common"     // TSS 库：通用工具
	"github.com/bnb-chain/tss-lib/v2/crypto"     // TSS 库：密码学原语
	"github.com/bnb-chain/tss-lib/v2/crypto/vss" // TSS 库：Feldman 秘密分享
	"github.com/bnb-chain/tss-lib/v2/test"       // TSS 库：测试工具
	"github.com/bnb-chain/tss-lib/v2/tss"        // TSS 库：核心协议
	"github.com/stretchr/testify/assert"         // 外部库：断言库（用于 assert.Equal 等）
)

// TestKeygenAndAddressGeneration_2 完整的 keygen 流程测试函数
// 功能说明：
//  1. 进行 keygen 生成密钥分片（3 个参与者生成分片）
//  2. 合并分片私钥得到完整私钥（所有份额的和）
//  3. 生成公钥（用私钥 × 生成点 G）
//  4. 从公钥派生出 Bitcoin 和 Ethereum 地址
//
// 参数：t *testing.T - Go 测试框架的测试对象，用于日志和断言
func TestKeygenAndAddressGeneration_2(t *testing.T) {
	// 第 28 行：初始化日志系统，设置日志级别为 "info"
	setUp("info")

	// 第 30 行：获取全局测试配置中的阈值（例如：1，表示 2-of-3 的签名阈值）
	threshold := testThreshold

	// 第 31 行：尝试从本地缓存加载预计算的 Paillier 安全素数和参与方 ID
	// 如果缓存存在，则使用缓存加快测试速度；否则从零开始生成
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)

	// 第 32 行：检查是否成功加载缓存
	if err != nil {
		// 第 33 行：如果没有缓存，输出信息提示将从零生成安全素数（耗时操作）
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")

		// 第 34 行：生成测试参与方 ID 列表（例如：3 个参与方的 ID）
		// testParticipants 是全局变量，通常为 3
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	// 打印 pIDs
	pIDsJSON, _ := json.MarshalIndent(pIDs, "", "  ")
	common.Logger.Infof("PartyIDs:\n%s", string(pIDsJSON))

	// 打印 fixtures
	fixturesJSON, _ := json.MarshalIndent(fixtures, "", "  ")
	common.Logger.Infof("Fixtures:\n%s", string(fixturesJSON))

	// 第 37 行：创建点对点通信上下文，包含所有参与方的身份信息
	// 这个上下文用于参与方之间进行消息路由
	p2pCtx := tss.NewPeerContext(pIDs)

	// 第 38 行：创建空的 LocalParty 切片，容量为参与方数量，用于存储所有参与方对象
	parties := make([]*LocalParty, 0, len(pIDs))

	// 第 40 行：创建错误通道，缓冲区大小为参与方数量，用于接收各参与方的错误
	errCh := make(chan *tss.Error, len(pIDs))

	// 第 41 行：创建消息输出通道，缓冲区大小为参与方数量，用于接收参与方发送的消息
	outCh := make(chan tss.Message, len(pIDs))

	// 第 42 行：创建结束通道，缓冲区大小为参与方数量，用于接收参与方的最终保存数据
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	// 第 44 行：获取共享的消息更新器函数，用于将消息路由给对应的参与方
	// 这个函数负责将一个参与方的消息传递给另一个参与方并触发更新
	updater := test.SharedPartyUpdater

	// 第 46-63 行：初始化所有参与方的循环
	// 这段代码为每个参与方创建一个 LocalParty 对象并启动协议
	for i := 0; i < len(pIDs); i++ {
		// 第 48 行：声明 LocalParty 类型的指针变量 P（稍后赋值）
		var P *LocalParty

		// 第 49 行：创建第 i 个参与方的协议参数
		// 参数包括：椭圆曲线（S256）、通信上下文、自身 ID、总参与方数、阈值
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)

		// 第 50 行：禁用 ModProof（模数证明），减少计算量（用于简化演示）
		params.SetNoProofMod()

		// 第 51 行：禁用 FacProof（因子证明），进一步减少计算量
		params.SetNoProofFac()

		// 第 52 行：检查是否有该参与方的预计算 Paillier 参数缓存
		if i < len(fixtures) {
			// 第 53 行：如果有缓存，使用缓存的 Paillier 私钥参数创建 LocalParty
			// 这可以大大加快测试速度（Paillier 密钥生成非常耗时）
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			// 第 55 行：如果没有缓存，创建新的 LocalParty（会自动生成新的 Paillier 参数）
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}

		// 第 57 行：将该参与方添加到 parties 切片中
		parties = append(parties, P)

		// 第 58 行：启动一个 goroutine（并发执行线程）来运行该参与方的协议
		go func(P *LocalParty) {
			// 第 59 行：调用参与方的 Start() 方法，开始执行 keygen 协议的第一轮
			if err := P.Start(); err != nil {
				// 第 60 行：如果启动过程中出错，将错误发送到错误通道
				errCh <- err
			}
		}(P)
	}

	// 第 65 行：开始 keygen 阶段的注释标记
	// PHASE: keygen

	// 第 66 行：声明计数器，记录有多少个参与方已完成 keygen
	// int32 类型是因为要在并发环境中安全地更新（虽然这里没有用原子操作，为简化）
	var ended int32

	// 第 67 行：创建切片来收集所有参与方的 keygen 结果
	// 每个参与方完成后会通过 endCh 通道发送其保存的数据
	var saveDataList []*LocalPartySaveData

	// 第 69 行：标签 "keygen:"，用于 break 语句跳出嵌套循环
	// 这样可以在内层代码中用 "break keygen" 跳出整个 keygen 阶段
keygen:
	// 第 70 行：开始无限循环，处理来自各通道的消息和事件
	for {
		// 第 71 行：select 语句等待多个通道中的任何一个就绪
		// 通道操作包括：错误通道、消息通道、结束通道
		select {

		// ========== 错误处理分支 ==========
		// 第 72 行：监听错误通道，如果有参与方报错就进入此分支
		case err := <-errCh:
			// 第 73 行：使用日志记录收到的错误
			common.Logger.Errorf("Error: %s", err)

			// 第 74 行：使用 assert.FailNow 立即停止测试并报告错误
			assert.FailNow(t, err.Error())

			// 第 75 行：跳出 keygen 循环（使用标签跳出外层循环）
			break keygen

		// ========== 消息处理分支 ==========
		// 第 77 行：监听消息输出通道，参与方发送消息时进入此分支
		case msg := <-outCh:
			// 第 78 行：获取消息的目标接收者列表
			// 如果是广播消息，dest 为 nil；如果是点对点消息，dest 包含单个接收者
			dest := msg.GetTo()

			// 第 79 行：检查是否为广播消息（dest == nil）
			if dest == nil { // broadcast!
				// 第 80 行：对所有参与方进行循环，将广播消息发送给除了发送者之外的所有人
				for _, P := range parties {
					// 第 81 行：检查该参与方是否是消息发送者
					if P.PartyID().Index == msg.GetFrom().Index {
						// 第 82 行：如果是发送者，跳过（不需要将消息发送回自己）
						continue
					}
					// 第 84 行：并发执行 updater 函数，将消息传递给该参与方并触发更新
					// updater 会调用参与方的 Update() 方法处理消息
					// errCh 用于捕获更新过程中的错误
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				// 第 86 行：处理点对点消息的情况

				// 第 87 行：检查消息的目标是否是发送者自己（这是一个错误）
				if dest[0].Index == msg.GetFrom().Index {
					// 第 88 行：如果发送者试图给自己发消息，这是逻辑错误，立即失败
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}

				// 第 91 行：将点对点消息发送给目标参与方（并发执行）
				// dest[0].Index 是接收方的索引，parties[dest[0].Index] 是接收方的对象
				go updater(parties[dest[0].Index], msg, errCh)
			}

		// ========== 完成处理分支 ==========
		// 第 94 行：监听结束通道，当参与方完成 keygen 时进入此分支
		case save := <-endCh:
			// 第 95 行：将该参与方的保存数据添加到列表中
			// LocalPartySaveData 包含：私钥份额（Xi）、公钥等关键数据
			saveDataList = append(saveDataList, save)

			// 第 96 行：增加完成计数器
			ended++

			// 第 97 行：检查是否所有参与方都已完成 keygen
			// len(pIDs) 是参与方总数（例如 3）
			if ended == int32(len(pIDs)) {
				// 第 98 行：输出日志表示 keygen 已完成
				t.Logf("✓ Keygen completed. Received save data from %d participants", ended)

				// ============================================
				// 步骤 1: 收集所有参与方的密钥分片
				// ============================================

				// 第 103 行：创建二维分片数组
				// allShares[i] 表示发送给第 i 个参与方的所有分片
				// allShares[i][j] 表示第 j 个参与方发送给第 i 个参与方的分片
				allShares := make([]vss.Shares, len(parties))

				// 第 104 行：外层循环，遍历每个参与方的分片集合
				for partyIdx := range parties {
					// 第 105 行：创建空分片切片，用于存储发送给该参与方的所有分片
					pShares := make(vss.Shares, 0)

					// 第 106 行：内层循环，遍历所有参与方
					for _, otherP := range parties {
						// 第 107 行：从其他参与方的临时数据中获取第 2 轮消息 1
						// kgRound2Message1s[i] 是发送给第 i 个参与方的消息
						vssMsgs := otherP.temp.kgRound2Message1s

						// 第 108 行：从消息中提取该参与方对当前参与方的分片值
						// share 是原始字节形式的分片
						share := vssMsgs[partyIdx].Content().(*KGRound2Message1).Share

						// 第 110-114 行：构造 vss.Share 结构体
						shareStruct := &vss.Share{
							Threshold: threshold,                    // 阈值（例如 1）
							ID:        otherP.PartyID().KeyInt(),    // 分片提供者的 ID
							Share:     new(big.Int).SetBytes(share), // 分片值（从字节转换为大整数）
						}

						// 第 115 行：将该分片添加到该参与方的分片列表中
						pShares = append(pShares, shareStruct)
					}

					// 第 117 行：将该参与方的完整分片集合存储到 allShares
					allShares[partyIdx] = pShares
				}

				// ============================================
				// 步骤 2: 合并分片私钥为完整私钥
				// ============================================

				// 第 123-125 行：说明注释
				// 每个参与者有一个秘密份额 xi（在 keygen 中生成）
				// 完整的主密钥是所有份额的和：x = x1 + x2 + x3 + ...
				// 这里我们遍历所有参与方的分片集合，重建每个参与者的份额，然后求和

				// 第 127 行：输出日志说明需要多少个分片来重建（需要 threshold+1 个）
				t.Logf("📦 Using threshold=%d, need threshold+1=%d shares for reconstruction", threshold, threshold+1)

				// 第 130 行：初始化主密钥为 0（用于累加所有份额）
				reconstructedPrivateKey := big.NewInt(0)

				// 第 131 行：创建模 N 的运算对象
				// N 是椭圆曲线的阶（order），用于模运算确保结果在有效范围内
				modN := common.ModInt(tss.S256().Params().N)

				// 第 133 行：遍历所有参与方的分片集合
				// 对于每个参与方，我们都有一个完整的分片集合（来自所有其他参与方）
				for _, pShares := range allShares {
					// 第 135 行：从该参与方的分片中取前 threshold+1 个
					// 这足以重建该参与方的秘密份额 xi
					// 例如：threshold=1，所以取前 2 个分片
					reconstructedShares := pShares[:threshold+1]

					// 第 136 行：使用 Lagrange 插值重建该参与方的秘密份额
					// ReConstruct 是 Feldman VSS 的核心函数
					// 输入：threshold+1 个分片
					// 输出：该参与方的原始秘密份额 xi
					xi, err := reconstructedShares.ReConstruct(tss.S256())

					// 第 137 行：断言重建过程没有错误
					assert.NoError(t, err, "private key reconstruction should not fail")

					// 第 138 行：断言重建的份额不为零（零份额是无效的）
					assert.NotZero(t, xi, "reconstructed xi should not be zero")

					// 第 141 行：使用模加法将该份额累加到主密钥中
					// modN.Add() 会自动进行模 N 运算，确保结果在 [0, N) 范围内
					reconstructedPrivateKey = modN.Add(reconstructedPrivateKey, xi)
				}

				// 第 144 行：输出重建后的私钥（十进制字符串形式）
				t.Logf("✓ Private Key (Hex): %s", reconstructedPrivateKey.String())

				// ============================================
				// 步骤 3: 从私钥生成公钥
				// ============================================

				// 第 149 行：输出日志说明开始派生公钥
				t.Log("Deriving public key from private key...")

				// 第 152 行：使用椭圆曲线标量乘法计算公钥
				// 公钥 = 私钥 × G（G 是椭圆曲线的生成点）
				// ScalarBaseMult 返回两个大整数：公钥的 X 坐标和 Y 坐标
				pkX, pkY := tss.EC().ScalarBaseMult(reconstructedPrivateKey.Bytes())

				// 第 154 行：创建 ECPoint 对象包装 X 和 Y 坐标
				// ECPoint 提供了一些便利方法来处理椭圆曲线上的点
				publicKey, err := crypto.NewECPoint(tss.S256(), pkX, pkY)

				// 第 155 行：检查公钥创建是否失败（例如点不在曲线上）
				if err != nil {
					// 第 156 行：如果失败，立即停止测试并报告错误
					t.Fatalf("Failed to create public key: %v", err)
				}

				// 第 159 行：输出公钥的 X 坐标
				t.Logf("✓ Public Key X: %s", pkX.String())

				// 第 160 行：输出公钥的 Y 坐标
				t.Logf("✓ Public Key Y: %s", pkY.String())

				// ========== 公钥验证 ==========

				// 第 163 行：断言 saveDataList 不为空（应该包含所有参与方的数据）
				assert.NotNil(t, saveDataList, "saveDataList should not be nil")

				// 第 164 行：断言 saveDataList 至少包含一个元素
				assert.Greater(t, len(saveDataList), 0, "saveDataList should contain data")

				// 第 166 行：获取第一个参与方的保存数据（其中包含 ECDSAPub）
				// 所有参与方应该有相同的公钥
				firstSave := saveDataList[0]

				// 第 167 行：断言重建的公钥 X 坐标与保存的公钥 X 坐标相同
				// 这验证了我们的重建过程是否正确
				assert.Equal(t, publicKey.X(), firstSave.ECDSAPub.X(), "public key X should match")

				// 第 168 行：断言重建的公钥 Y 坐标与保存的公钥 Y 坐标相同
				assert.Equal(t, publicKey.Y(), firstSave.ECDSAPub.Y(), "public key Y should match")

				// 第 169 行：输出日志表示公钥验证通过
				t.Log("✓ Public key verification passed")

				// 第 172 行：遍历所有参与方的保存数据
				for i, saveData := range saveDataList {
					// 第 173-174 行：断言第 i 个参与方保存的公钥 X 坐标与重建的公钥相同
					assert.Equal(t, publicKey.X(), saveData.ECDSAPub.X(),
						"party %d public key X should match", i)

					// 第 175-176 行：断言第 i 个参与方保存的公钥 Y 坐标与重建的公钥相同
					assert.Equal(t, publicKey.Y(), saveData.ECDSAPub.Y(),
						"party %d public key Y should match", i)
				}

				// 第 178 行：输出日志表示所有参与方都有相同的公钥
				t.Log("✓ All parties have same public key")

				// ============================================
				// 步骤 4: 从公钥派生出 Bitcoin/Ethereum 地址
				// ============================================

				// 第 183 行：输出日志说明开始派生地址
				t.Log("Deriving address from public key...")

				// 第 186 行：调用辅助函数生成 Bitcoin SegWit 地址
				// 该函数会：1) 压缩公钥 2) 计算 Hash160 3) 编码为 bech32 格式
				bitcoinAddress := deriveSegwitAddress(pkX, pkY)

				// 第 187 行：输出生成的 Bitcoin 地址
				t.Logf("✓ Bitcoin SegWit Address: %s", bitcoinAddress)

				// 第 190 行：调用辅助函数生成 Ethereum 地址
				// 该函数会：1) 将公钥展平为 64 字节 2) 计算 Keccak256 哈希 3) 取最后 20 字节
				ethereumAddress := deriveEthereumAddress(pkX, pkY)

				// 第 191 行：输出生成的 Ethereum 地址（带 0x 前缀）
				t.Logf("✓ Ethereum Address: 0x%s", ethereumAddress)

				// ========== 生成标准 ECDSA 密钥对 ==========

				// 第 194-201 行：构造标准的 Go ECDSA PrivateKey 结构体
				// 这个结构体可以用于标准的 ECDSA 签名和验证操作
				ecdsaSK := ecdsa.PrivateKey{
					// 第 195-199 行：公钥部分
					PublicKey: ecdsa.PublicKey{
						Curve: tss.S256(), // 椭圆曲线：secp256k1
						X:     pkX,        // 公钥 X 坐标
						Y:     pkY,        // 公钥 Y 坐标
					},
					// 第 200 行：私钥部分（重建的主密钥）
					D: reconstructedPrivateKey,
				}

				// 第 204 行：验证公钥是否在椭圆曲线上
				// IsOnCurve 检查点 (pkX, pkY) 是否满足椭圆曲线方程
				assert.True(t, ecdsaSK.IsOnCurve(pkX, pkY), "public key must be on curve")

				// 第 207 行：调用辅助函数打印密钥生成摘要
				// 这会输出所有关键密钥信息的十六进制形式和地址
				printKeySummary(t, reconstructedPrivateKey, pkX, pkY, bitcoinAddress, ethereumAddress)

				// 第 209 行：输出日志表示整个测试通过
				t.Log("✓ Complete key generation and address derivation test passed!")

				// 第 211 行：使用标签跳出 keygen 循环，结束测试
				break keygen
			}
		}
	}
}
