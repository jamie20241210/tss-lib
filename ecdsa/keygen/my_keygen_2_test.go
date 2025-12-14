// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/assert"
)

// TestKeygenAndAddressGeneration 完整的 keygen 流程：
// 1. 进行 keygen 生成密钥分片
// 2. 合并分片私钥得到完整私钥
// 3. 生成公钥
// 4. 从公钥派生出 Bitcoin 和 Ethereum 地址
func TestKeygenAndAddressGeneration_2(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	// 初始化各方
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
	var saveDataList []*LocalPartySaveData // 收集所有的 save data

keygen:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			saveDataList = append(saveDataList, save) // 保存 save data
			ended++
			if ended == int32(len(pIDs)) {
				t.Logf("✓ Keygen completed. Received save data from %d participants", ended)

				// ============================================
				// 步骤 1: 收集所有参与方的密钥分片
				// ============================================
				allShares := make([]vss.Shares, len(parties))
				for partyIdx := range parties {
					pShares := make(vss.Shares, 0)
					for _, otherP := range parties {
						vssMsgs := otherP.temp.kgRound2Message1s
						share := vssMsgs[partyIdx].Content().(*KGRound2Message1).Share

						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        otherP.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					allShares[partyIdx] = pShares
				}

				// ============================================
				// 步骤 2: 合并分片私钥为完整私钥
				// ============================================
				// 每个参与者都有一个秘密份额 xi
				// 完整的主密钥是所有份额的和: x = x1 + x2 + x3 + ...
				// 所以我们需要遍历所有参与方的分片集合，重建出每个参与者的份额，然后求和

				t.Logf("📦 Using threshold=%d, need threshold+1=%d shares for reconstruction", threshold, threshold+1)

				// 从所有参与者的分片重建主密钥
				reconstructedPrivateKey := big.NewInt(0)
				modN := common.ModInt(tss.S256().Params().N)

				for _, pShares := range allShares {
					// 对每个参与者的分片集合，取前 threshold+1 个进行重建
					reconstructedShares := pShares[:threshold+1]
					xi, err := reconstructedShares.ReConstruct(tss.S256())
					assert.NoError(t, err, "private key reconstruction should not fail")
					assert.NotZero(t, xi, "reconstructed xi should not be zero")

					// 累加所有的份额
					reconstructedPrivateKey = modN.Add(reconstructedPrivateKey, xi)
				}

				t.Logf("✓ Private Key (Hex): %s", reconstructedPrivateKey.String())

				// ============================================
				// 步骤 3: 从私钥生成公钥
				// ============================================
				t.Log("Deriving public key from private key...")

				// 使用椭圆曲线标量乘法
				pkX, pkY := tss.EC().ScalarBaseMult(reconstructedPrivateKey.Bytes())

				publicKey, err := crypto.NewECPoint(tss.S256(), pkX, pkY)
				if err != nil {
					t.Fatalf("Failed to create public key: %v", err)
				}

				t.Logf("✓ Public Key X: %s", pkX.String())
				t.Logf("✓ Public Key Y: %s", pkY.String())

				// 验证：公钥应该与保存的公钥一致
				assert.NotNil(t, saveDataList, "saveDataList should not be nil")
				assert.Greater(t, len(saveDataList), 0, "saveDataList should contain data")

				firstSave := saveDataList[0]
				assert.Equal(t, publicKey.X(), firstSave.ECDSAPub.X(), "public key X should match")
				assert.Equal(t, publicKey.Y(), firstSave.ECDSAPub.Y(), "public key Y should match")
				t.Log("✓ Public key verification passed")

				// 验证所有参与方都有相同的公钥
				for i, saveData := range saveDataList {
					assert.Equal(t, publicKey.X(), saveData.ECDSAPub.X(),
						"party %d public key X should match", i)
					assert.Equal(t, publicKey.Y(), saveData.ECDSAPub.Y(),
						"party %d public key Y should match", i)
				}
				t.Log("✓ All parties have same public key")

				// ============================================
				// 步骤 4: 从公钥派生出 Bitcoin/Ethereum 地址
				// ============================================
				t.Log("Deriving address from public key...")

				// Bitcoin SegWit 地址生成
				bitcoinAddress := deriveSegwitAddress(pkX, pkY)
				t.Logf("✓ Bitcoin SegWit Address: %s", bitcoinAddress)

				// Ethereum 地址生成（使用 Keccak256）
				ethereumAddress := deriveEthereumAddress(pkX, pkY)
				t.Logf("✓ Ethereum Address: 0x%s", ethereumAddress)

				// 生成标准 ECDSA 私钥结构
				ecdsaSK := ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{
						Curve: tss.S256(),
						X:     pkX,
						Y:     pkY,
					},
					D: reconstructedPrivateKey,
				}

				// 验证私钥在曲线上
				assert.True(t, ecdsaSK.IsOnCurve(pkX, pkY), "public key must be on curve")

				// 打印摘要
				printKeySummary(t, reconstructedPrivateKey, pkX, pkY, bitcoinAddress, ethereumAddress)

				t.Log("✓ Complete key generation and address derivation test passed!")

				break keygen
			}
		}
	}
}
