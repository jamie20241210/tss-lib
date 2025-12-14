// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// test_utils.go 文件功能说明：
// 这是一个测试工具文件，主要用于：
// 1. 加载预生成的 keygen 测试数据（fixture）
// 2. 管理测试参数（参与方数量、阈值）
// 3. 处理测试数据的序列化和反序列化
// 4. 生成测试用的 PartyID 列表

package keygen

import (
	"encoding/json" // 标准库：JSON 编码解码
	"fmt"           // 标准库：格式化字符串
	"io/ioutil"     // 标准库：读写文件（已弃用，但这里还在用）
	"math/big"      // 标准库：大整数运算
	"math/rand"     // 标准库：随机数生成
	"path/filepath" // 标准库：文件路径处理
	"runtime"       // 标准库：运行时信息（获取调用者信息）
	"sort"          // 标准库：排序

	"github.com/pkg/errors" // 外部库：更好的错误处理

	"github.com/bnb-chain/tss-lib/v2/test" // TSS 库：测试工具
	"github.com/bnb-chain/tss-lib/v2/tss"  // TSS 库：核心定义
)

// ========== 常量定义 ==========

const (
	// TestParticipants 定义了测试中参与方的总数量
	// 注释说明：要改变这个参数，必须先删除 test/_fixtures/ 中的测试数据文件
	// 然后单独运行 keygen 测试，这样会生成新的测试数据文件
	// 签名和重分享测试会使用这些新生成的数据
	TestParticipants = test.TestParticipants // 例如：3（从 test 包导入）

	// TestThreshold 定义了签名时所需的最小参与方数量
	// 计算方式：参与方总数 / 2
	// 例如：3 / 2 = 1，表示 2-of-3（需要至少 2 个参与方签名）
	TestThreshold = test.TestParticipants / 2
)

const (
	// testFixtureDirFormat 定义了测试数据目录的格式
	// %s 会被替换为源代码所在目录
	// ../../test/_ecdsa_fixtures 表示回溯到上上级目录，然后进入 test/_ecdsa_fixtures
	testFixtureDirFormat = "%s/../../test/_ecdsa_fixtures"

	// testFixtureFileFormat 定义了单个测试数据文件的格式
	// 文件名为 keygen_data_0.json, keygen_data_1.json, keygen_data_2.json 等
	testFixtureFileFormat = "keygen_data_%d.json"
)

// ========== 函数定义 ==========

// LoadKeygenTestFixtures 从本地文件加载预生成的 keygen 测试数据
//
// 参数说明：
//
//	qty: 需要加载多少个参与方的数据（例如：3）
//	optionalStart: 可选参数，指定从第几个参与方开始加载（默认为 0）
//
// 返回值说明：
//
//	[]LocalPartySaveData: 加载的所有参与方的 keygen 保存数据切片
//	                      每个元素包含一个参与方的完整密钥信息（包括私密份额）
//	tss.SortedPartyIDs: 参与方 ID 列表（已按 ShareID 排序）
//	error: 加载或解析过程中的错误（如文件不存在或 JSON 无效）
//
// 功能详解：
//  1. 从磁盘读取 JSON 格式的测试数据文件
//  2. 反序列化 JSON 为 LocalPartySaveData 结构体
//  3. 为 ECPoint（椭圆曲线点）设置正确的曲线信息
//  4. 生成参与方 ID 列表并进行排序
func LoadKeygenTestFixtures(qty int, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	// 第 37 行：创建空切片，用于存储加载的 keygen 数据
	// 容量预设为 qty，避免后续的内存重新分配
	keys := make([]LocalPartySaveData, 0, qty)

	// 第 38 行：初始化起始索引为 0（默认从第一个参与方开始）
	start := 0

	// 第 39-41 行：检查是否提供了可选的起始索引
	if 0 < len(optionalStart) {
		// 第 40 行：如果提供了，使用提供的值
		start = optionalStart[0]
	}

	// 第 42 行：循环加载 qty 个参与方的数据
	// 从 start 索引开始，加载到 qty 个数据为止
	// 例如：start=0, qty=3 会加载索引 0, 1, 2 的三个文件
	for i := start; i < qty; i++ {
		// 第 43 行：根据参与方索引生成测试数据文件的完整路径
		// 例如：/path/to/test/_ecdsa_fixtures/keygen_data_0.json
		fixtureFilePath := makeTestFixtureFilePath(i)

		// 第 44 行：从文件系统读取 JSON 文件内容
		// ioutil.ReadFile 返回文件的完整二进制内容
		bz, err := ioutil.ReadFile(fixtureFilePath)

		// 第 45 行：检查文件读取是否出错
		if err != nil {
			// 第 46-48 行：如果出错，返回错误信息并说明文件路径和建议
			// 错误信息告诉用户需要先运行 keygen 测试生成数据文件
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}

		// 第 50 行：声明 LocalPartySaveData 结构体，用于存储反序列化的数据
		// LocalPartySaveData 包含该参与方的所有 keygen 数据：
		// - Xi: 该参与方的秘密份额
		// - ECDSAPub: 共享的 ECDSA 公钥
		// - BigXj: 所有参与方的公钥份额
		// - LocalPreParams: Paillier 密钥和相关参数
		var key LocalPartySaveData

		// 第 51 行：将 JSON 字节数组反序列化为 LocalPartySaveData 结构体
		// json.Unmarshal 解析 JSON 并填充结构体字段
		if err = json.Unmarshal(bz, &key); err != nil {
			// 第 52-54 行：如果 JSON 解析失败，返回详细的错误信息
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}

		// 第 56-58 行：为所有 ECPoint 对象设置椭圆曲线信息
		// BigXj 是 []*crypto.ECPoint 类型，包含所有参与方的公钥份额
		for _, kbxj := range key.BigXj {
			// 第 57 行：调用 SetCurve() 为该 ECPoint 设置使用的椭圆曲线（S256 = secp256k1）
			// 这是必需的，因为 JSON 反序列化不包含曲线信息，需要手动设置
			kbxj.SetCurve(tss.S256())
		}

		// 第 59 行：为主 ECDSA 公钥设置椭圆曲线
		// ECDSAPub 是所有参与方共享的主公钥
		key.ECDSAPub.SetCurve(tss.S256())

		// 第 60 行：将加载和初始化后的数据添加到 keys 切片
		keys = append(keys, key)
	}

	// 第 62 行：创建 UnSortedPartyIDs 切片，用于生成参与方 ID 列表
	// 大小为加载的 keys 数量
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))

	// 第 63 行：遍历所有加载的 keys，为每个参与方创建 PartyID
	for i, key := range keys {
		// 第 64 行：生成参与方的名称/绰号
		// 例如：当 start=0, i=0 时，pMoniker="1"
		// 使用 i+start+1 使得名称从 1 开始编号（而不是 0）
		pMoniker := fmt.Sprintf("%d", i+start+1)

		// 第 65 行：创建新的 PartyID 对象
		// 参数说明：
		// - pMoniker: 参与方的名称（用于日志和显示，例如 "1"）
		// - pMoniker: 参与方的别名（通常与名称相同）
		// - key.ShareID: 该参与方的秘密 ID（在 keygen 时生成的唯一标识符）
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}

	// 第 67 行：对参与方 ID 列表进行排序
	// SortPartyIDs 会按照 ShareID 的大小排序
	// 排序后的 ID 列表在后续通信中用于确定消息的接收顺序
	sortedPIDs := tss.SortPartyIDs(partyIDs)

	// 第 68 行：返回加载的数据和排序后的参与方 ID 列表
	return keys, sortedPIDs, nil
}

// LoadKeygenTestFixturesRandomSet 从本地文件随机加载指定数量的 keygen 测试数据
//
// 参数说明：
//
//	qty: 需要加载多少个参与方的数据（例如：2）
//	fixtureCount: 总共有多少个可用的测试数据文件（例如：3）
//
// 返回值说明：
//
//	[]LocalPartySaveData: 随机加载的参与方 keygen 数据
//	tss.SortedPartyIDs: 参与方 ID 列表（已按 ShareID 排序）
//	error: 加载过程中的错误
//
// 功能详解：
//
//	这个函数与 LoadKeygenTestFixtures 的区别是：
//	- LoadKeygenTestFixtures 按顺序加载（例如：0, 1, 2）
//	- LoadKeygenTestFixturesRandomSet 随机选择加载（例如：0, 2）
//	这对于测试签名协议很有用，因为签名不需要所有 keygen 参与方
//	通常只需要 threshold+1 个参与方
func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	// 第 72 行：创建切片存储加载的数据
	keys := make([]LocalPartySaveData, 0, qty)

	// 第 73 行：创建 map，用于追踪已选择的文件索引
	// key 是文件索引（0, 1, 2 等），value 是占位符
	plucked := make(map[int]interface{}, qty)

	// 第 74-79 行：随机选择 qty 个不同的文件索引
	// 这个循环使用轮询方式确保即使随机数不够幸运，最终也能选择足够的索引
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		// 第 75 行：检查索引 i 是否已被选择
		_, have := plucked[i]

		// 第 76 行：生成 0.5 的随机概率，决定是否选择该索引
		// pluck := rand.Float32() < 0.5 返回 true 的概率约为 50%
		// 条件 !have && pluck 表示：如果该索引未被选择且随机数满足条件，则选择
		if pluck := rand.Float32() < 0.5; !have && pluck {
			// 第 77 行：将该索引标记为已选择
			plucked[i] = new(struct{}) // 值是空结构体，只用作标记
		}
	}

	// 第 80 行：遍历已选择的所有索引
	for i := range plucked {
		// 第 81 行：根据索引生成文件路径
		fixtureFilePath := makeTestFixtureFilePath(i)

		// 第 82 行：读取文件内容
		bz, err := ioutil.ReadFile(fixtureFilePath)

		// 第 83 行：检查读取错误
		if err != nil {
			// 第 84-86 行：返回错误信息
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}

		// 第 88 行：声明数据结构体
		var key LocalPartySaveData

		// 第 89 行：反序列化 JSON
		if err = json.Unmarshal(bz, &key); err != nil {
			// 第 90-92 行：返回错误信息
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}

		// 第 94-96 行：为 ECPoint 设置椭圆曲线（与前一个函数相同）
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())

		// 第 98 行：将加载的数据添加到 keys 切片
		keys = append(keys, key)
	}

	// 第 100 行：创建 PartyID 列表
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))

	// 第 101 行：初始化索引计数器（用于生成 PartyID 列表）
	j := 0

	// 第 102 行：遍历已选择的索引
	for i := range plucked {
		// 第 103 行：获取已加载数据中的第 j 个元素
		key := keys[j]

		// 第 104 行：生成参与方名称（从 1 开始编号）
		pMoniker := fmt.Sprintf("%d", i+1)

		// 第 105 行：创建 PartyID
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)

		// 第 106 行：递增索引计数器
		j++
	}

	// 第 108 行：对参与方 ID 列表进行排序
	sortedPIDs := tss.SortPartyIDs(partyIDs)

	// 第 109 行：按 ShareID 对 keys 切片进行排序
	// 这确保 keys 和 sortedPIDs 的顺序一致
	// 使用 Cmp() 方法比较大整数的大小，-1 表示小于
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })

	// 第 110 行：返回随机选择的数据和排序后的参与方 ID
	return keys, sortedPIDs, nil
}

// LoadNTildeH1H2FromTestFixture 从测试数据文件中加载 Paillier 密码学参数
//
// 参数说明：
//
//	idx: 参与方的索引（0, 1, 2 等）
//
// 返回值说明：
//
//	NTildei: Paillier 安全参数 N-tilde（由两个大素数的乘积组成）
//	h1i: Paillier 密码学参数 h1
//	h2i: Paillier 密码学参数 h2
//	error: 加载过程中的错误
//
// 功能详解：
//
//	这个函数是一个便利函数，用于快速加载单个参与方的 Paillier 参数
//	这些参数在签名协议中用于零知识证明和安全计算
func LoadNTildeH1H2FromTestFixture(idx int) (NTildei, h1i, h2i *big.Int, err error) {
	// 第 114 行：加载从 0 到 idx（包含）的所有 keygen 数据
	// 这样可以确保获取到目标索引的数据
	fixtures, _, err := LoadKeygenTestFixtures(idx + 1)

	// 第 115 线：检查加载是否出错
	if err != nil {
		// 第 116 行：如果出错，直接返回（err 已设置，NTildei/h1i/h2i 为 nil）
		return
	}

	// 第 118 行：获取第 idx 个参与方的数据
	fixture := fixtures[idx]

	// 第 119 行：从该参与方的数据中提取 N-tilde、h1、h2 参数
	// 这些是该参与方在 keygen 时生成的 Paillier 参数
	NTildei, h1i, h2i = fixture.NTildei, fixture.H1i, fixture.H2i

	// 第 120 行：返回提取的参数（err 为 nil）
	return
}

// makeTestFixtureFilePath 生成测试数据文件的完整路径
//
// 参数说明：
//
//	partyIndex: 参与方的索引（0, 1, 2 等）
//
// 返回值说明：
//
//	string: 测试数据文件的完整绝对路径
//
// 功能详解：
//
//	这个函数使用 Go 的 runtime 包获取当前源代码文件的位置
//	然后相对于该位置构建测试数据目录的路径
//	这样可以确保无论测试从哪个目录运行，都能找到正确的测试数据文件
//
// 示例：
//
//	partyIndex=0 → "/path/to/project/test/_ecdsa_fixtures/keygen_data_0.json"
//	partyIndex=1 → "/path/to/project/test/_ecdsa_fixtures/keygen_data_1.json"
func makeTestFixtureFilePath(partyIndex int) string {
	// 第 124 行：获取当前函数的调用者信息
	// runtime.Caller(0) 返回当前函数的信息
	// callerFileName 是当前文件的完整路径（例如：/path/to/test_utils.go）
	_, callerFileName, _, _ := runtime.Caller(0)

	// 第 125 行：获取当前文件所在的目录
	// filepath.Dir() 返回路径的目录部分
	// 例如：/path/to/keygen（不包含 test_utils.go 文件名）
	srcDirName := filepath.Dir(callerFileName)

	// 第 126 行：构造测试数据目录的完整路径
	// testFixtureDirFormat = "%s/../../test/_ecdsa_fixtures"
	// 例如：/path/to/test/_ecdsa_fixtures
	// ../../ 表示向上回溯两级目录（从 ecdsa/keygen 回到 test）
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)

	// 第 127 行：构造完整的文件路径
	// testFixtureFileFormat = "keygen_data_%d.json"
	// 例如：/path/to/test/_ecdsa_fixtures/keygen_data_0.json
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
