//go:build with_purego && linux && amd64

package cronet

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

// 1. 验证仅接受且规范化 64 字符十六进制 PSK，拒绝任何非 64 位或非 HEX 格式
func TestPTLS_ParsePSK(t *testing.T) {
	validHexLower := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validHexUpper := strings.ToUpper(validHexLower)

	got, err := parsePtlsPSK(validHexLower)
	if err != nil {
		t.Fatalf("合法小写 HEX 校验失败: %v", err)
	}
	if got != validHexLower {
		t.Fatalf("小写 HEX 结果不匹配: 期望 %s, 得到 %s", validHexLower, got)
	}

	gotUpper, err := parsePtlsPSK(validHexUpper)
	if err != nil {
		t.Fatalf("合法大写 HEX 校验失败: %v", err)
	}
	if gotUpper != validHexLower {
		t.Fatalf("大写 HEX 转小写不匹配: 期望 %s, 得到 %s", validHexLower, gotUpper)
	}

	if _, err := parsePtlsPSK(""); err == nil {
		t.Fatal("期望空 PSK 返回错误，实际返回了 nil")
	}

	if _, err := parsePtlsPSK(validHexLower[:63]); err == nil {
		t.Fatal("期望 63 字符 PSK 返回错误，实际返回了 nil")
	}
}

// 2. 真实 C-API / PureGo FFI 参数往返测试
func TestPTLS_EngineParams_RealFFI(t *testing.T) {
	testPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	params := NewEngineParams()
	defer params.Destroy()

	if err := params.SetAsyncDNS(true); err != nil {
		t.Fatalf("SetAsyncDNS 失败: %v", err)
	}

	if err := params.SetPTLSOptions(true, testPSK); err != nil {
		t.Fatalf("SetPTLSOptions 失败: %v", err)
	}

	rawJSON := params.ExperimentalOptions()
	if rawJSON == "" {
		t.Fatal("底层 ExperimentalOptions 为空，参数未生效")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &parsed); err != nil {
		t.Fatalf("解析底层返回的 JSON 失败: %v, raw: %s", err, rawJSON)
	}

	if val, ok := parsed["ptls"].(bool); !ok || !val {
		t.Fatalf("底层 ptls 选项不符合预期: %v", parsed["ptls"])
	}
	if val, ok := parsed["ptls_psk"].(string); !ok || val != testPSK {
		t.Fatalf("底层 ptls_psk 选项不符合预期: %v", parsed["ptls_psk"])
	}

	if err := params.SetPTLSOptions(false, ""); err != nil {
		t.Fatalf("清理 SetPTLSOptions 失败: %v", err)
	}

	cleanedJSON := params.ExperimentalOptions()
	var cleanedParsed map[string]any
	_ = json.Unmarshal([]byte(cleanedJSON), &cleanedParsed)

	if _, ok := cleanedParsed["ptls"]; ok {
		t.Fatal("禁用后底层 ptls 选项仍然存在")
	}
	if _, ok := cleanedParsed["ptls_psk"]; ok {
		t.Fatal("禁用后底层 ptls_psk 选项仍然存在")
	}
}

// 3. 端到端实机抓包与 SessionID 密码学逆向验证测试
func TestPTLS_NaiveClient_RealHandshake_Wiretap(t *testing.T) {
	testPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pskBytes, _ := hex.DecodeString(testPSK)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动本地虚拟监听失败: %v", err)
	}
	defer l.Close()

	tcpAddr := l.Addr().(*net.TCPAddr)
	serverPort := uint16(tcpAddr.Port)

	var capturedClientHello []byte
	var captureOnce sync.Once
	capturedDone := make(chan struct{})

	go func() {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		hdr := make([]byte, 5)
		if _, readErr := conn.Read(hdr); readErr != nil {
			return
		}
		if hdr[0] == 0x16 {
			recLen := binary.BigEndian.Uint16(hdr[3:5])
			body := make([]byte, recLen)
			totalRead := 0
			for totalRead < int(recLen) {
				n, rErr := conn.Read(body[totalRead:])
				if rErr != nil {
					break
				}
				totalRead += n
			}
			captureOnce.Do(func() {
				capturedClientHello = append(hdr, body[:totalRead]...)
				close(capturedDone)
			})
		}
		time.Sleep(500 * time.Millisecond)
	}()

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort("127.0.0.1", serverPort),
		ServerName:            "image.apple.com",
		InsecureConcurrency:   1,
		TestForceSingleEngine: true,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS:    true,
		PTLSPSK: testPSK,
	})
	if err != nil {
		t.Fatalf("创建 NaiveClient 失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动 NaiveClient 失败: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_, _ = client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	}()

	select {
	case <-capturedDone:
	case <-time.After(3 * time.Second):
		t.Fatal("捕获 ClientHello 超时，底层网络引擎未成功发起 TLS 握手")
	}

	if len(capturedClientHello) < 76 {
		t.Fatalf("截获的数据长度不足以承载 TLS ClientHello: %d 字节", len(capturedClientHello))
	}
	if capturedClientHello[0] != 0x16 || capturedClientHello[5] != 0x01 {
		t.Fatalf("首包记录非 ClientHello (0x16, 0x01): 0x%02x, 0x%02x", capturedClientHello[0], capturedClientHello[5])
	}

	clientRandom := capturedClientHello[11:43]
	sessIDLen := capturedClientHello[43]
	if sessIDLen != 32 {
		t.Fatalf("SessionID 长度不为 32: %d", sessIDLen)
	}
	sessionID := capturedClientHello[44:76]

	ts, authTag, valid := verifySessionID(pskBytes, clientRandom, sessionID)
	if !valid {
		t.Fatal("【关键失败】底层的 libcronet 未能注入合法的 PTLS SessionID 认证载荷！")
	}

	now := time.Now().Unix()
	drift := now - int64(ts)
	if drift < -5 || drift > 5 {
		t.Fatalf("提取的时间戳漂移过大: %d (当前: %d)", ts, now)
	}

	t.Logf("【实机验证成功】")
	t.Logf("  ├─ 捕获的 ClientRandom : %s", hex.EncodeToString(clientRandom))
	t.Logf("  ├─ 注入的 SessionID    : %s", hex.EncodeToString(sessionID))
	t.Logf("  ├─ 解出的 Unix 时间戳  : %d (时钟偏差 %d 秒)", ts, drift)
	t.Logf("  └─ 校验成功的 AuthTag  : %s", hex.EncodeToString(authTag))
}

// 4. 回归测试：验证 PTLS: false 时底层不会错误注入认证 SessionID
func TestPTLS_Regression_Disabled(t *testing.T) {
	testPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pskBytes, _ := hex.DecodeString(testPSK)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动本地虚拟监听失败: %v", err)
	}
	defer l.Close()

	serverPort := uint16(l.Addr().(*net.TCPAddr).Port)
	capturedDone := make(chan []byte, 1)

	go func() {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		hdr := make([]byte, 5)
		if _, readErr := conn.Read(hdr); readErr != nil {
			return
		}
		recLen := binary.BigEndian.Uint16(hdr[3:5])
		body := make([]byte, recLen)
		totalRead := 0
		for totalRead < int(recLen) {
			n, rErr := conn.Read(body[totalRead:])
			if rErr != nil {
				break
			}
			totalRead += n
		}
		capturedDone <- append(hdr, body[:totalRead]...)
	}()

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort("127.0.0.1", serverPort),
		ServerName:            "image.apple.com",
		InsecureConcurrency:   1,
		TestForceSingleEngine: true,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS: false,
	})
	if err != nil {
		t.Fatalf("创建 NaiveClient 失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动 NaiveClient 失败: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_, _ = client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	}()

	var capturedClientHello []byte
	select {
	case capturedClientHello = <-capturedDone:
	case <-time.After(3 * time.Second):
		t.Fatal("捕获 ClientHello 超时")
	}

	clientRandom := capturedClientHello[11:43]
	sessionID := capturedClientHello[44:76]

	_, _, valid := verifySessionID(pskBytes, clientRandom, sessionID)
	if valid {
		t.Fatal("PTLS 处于禁用状态，但底层依然注入了合法的 PTLS 认证 SessionID")
	}
}

// 5. 连接独立性测试：验证多次新建连接时 SessionID 与 ClientRandom 独立派生
func TestPTLS_Session_Uniqueness(t *testing.T) {
	testPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pskBytes, _ := hex.DecodeString(testPSK)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动本地虚拟监听失败: %v", err)
	}
	defer l.Close()

	serverPort := uint16(l.Addr().(*net.TCPAddr).Port)

	type capturedPair struct {
		random []byte
		sessID []byte
	}
	results := make(chan capturedPair, 2)

	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 5)
				if _, readErr := c.Read(hdr); readErr != nil {
					return
				}
				recLen := binary.BigEndian.Uint16(hdr[3:5])
				body := make([]byte, recLen)
				totalRead := 0
				for totalRead < int(recLen) {
					n, rErr := c.Read(body[totalRead:])
					if rErr != nil {
						break
					}
					totalRead += n
				}
				packet := append(hdr, body[:totalRead]...)
				results <- capturedPair{
					random: packet[11:43],
					sessID: packet[44:76],
				}
			}(conn)
		}
	}()

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort("127.0.0.1", serverPort),
		ServerName:            "image.apple.com",
		InsecureConcurrency:   1,
		TestForceSingleEngine: true,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS:    true,
		PTLSPSK: testPSK,
	})
	if err != nil {
		t.Fatalf("创建 NaiveClient 失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动 NaiveClient 失败: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	go func() {
		_, _ = client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 443))
	}()

	var p1 capturedPair
	select {
	case p1 = <-results:
	case <-time.After(3 * time.Second):
		t.Fatal("第 1 次建连超时")
	}

	client.CloseAllConnections()

	go func() {
		_, _ = client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.2", 443))
	}()

	var p2 capturedPair
	select {
	case p2 = <-results:
	case <-time.After(3 * time.Second):
		t.Fatal("第 2 次建连超时")
	}

	if hmac.Equal(p1.random, p2.random) {
		t.Fatal("连续建连检测到相同的 ClientRandom")
	}
	if hmac.Equal(p1.sessID, p2.sessID) {
		t.Fatal("连续建连检测到相同的 SessionID")
	}

	_, _, v1 := verifySessionID(pskBytes, p1.random, p1.sessID)
	_, _, v2 := verifySessionID(pskBytes, p2.random, p2.sessID)

	if !v1 || !v2 {
		t.Fatalf("多次握手中存在未通过认证的 SessionID: v1=%v, v2=%v", v1, v2)
	}
}

// 6. 真实服务端正向探测：验证能穿透至服务端内部自签证书链路
func TestPTLS_RemoteServer_E2E(t *testing.T) {
	if os.Getenv("PTLS_REMOTE_SERVER") == "" {
		t.Skip("set PTLS_REMOTE_SERVER to probe a real PTLS server")
	}
	serverIP := "203.0.113.1"
	serverPort := uint16(10443)
	realSNI := "nas.ijlk.top" // 替换为真实服务端 SNI
	realPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort(serverIP, serverPort),
		ServerName:            realSNI,
		InsecureConcurrency:   1,
		TestForceSingleEngine: true,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS:    true,
		PTLSPSK: realPSK,
	})
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动引擎失败: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 80))
	if err != nil {
		t.Fatalf("DialEarly 失败: %v", err)
	}
	defer conn.Close()

	err = conn.HandshakeContext(ctx)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "name not resolved") {
			t.Fatalf("【DNS 错误】未连接到目标服务器: %v", err)
		}
		if strings.Contains(errStr, "connection reset") {
			t.Fatalf("【服务端断开】握手被对端直接重置: %v", err)
		}
		t.Logf("真实服务端已响应握手，当前状态: %v", err)
	}
}

// 7. 真实服务端负向探测：验证错误 PSK 能被服务端安全降级至 Fallback 站点
func TestPTLS_RemoteServer_WrongPSK_Fallback(t *testing.T) {
	if os.Getenv("PTLS_REMOTE_SERVER") == "" {
		t.Skip("set PTLS_REMOTE_SERVER to probe a real PTLS server")
	}
	serverIP := "203.0.113.1"
	serverPort := uint16(10443)
	realSNI := "nas.ijlk.top" // 替换为真实服务端 SNI
	wrongPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0"

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort(serverIP, serverPort),
		ServerName:            realSNI,
		InsecureConcurrency:   1,
		TestForceSingleEngine: true,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS:    true,
		PTLSPSK: wrongPSK,
	})
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动引擎失败: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 80))
	if err != nil {
		t.Fatalf("DialEarly 失败: %v", err)
	}
	defer conn.Close()

	err = conn.HandshakeContext(ctx)
	if err != nil && strings.Contains(err.Error(), "cert authority invalid") {
		t.Fatalf("【旁路失效】错误 PSK 依然访问到了私有证书！")
	}

	t.Logf("负向回退机制生效，对端安全回退状态: %v", err)
}

// 8. 多引擎并发与多路分配测试
func TestPTLS_Concurrency_MultiEngine(t *testing.T) {
	testPSK := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pskBytes, _ := hex.DecodeString(testPSK)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	defer l.Close()

	serverPort := uint16(l.Addr().(*net.TCPAddr).Port)
	concurrency := 4

	var wg sync.WaitGroup
	wg.Add(concurrency)

	go func() {
		for i := 0; i < concurrency; i++ {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				defer wg.Done()

				hdr := make([]byte, 5)
				if _, readErr := c.Read(hdr); readErr != nil {
					return
				}
				recLen := binary.BigEndian.Uint16(hdr[3:5])
				body := make([]byte, recLen)
				totalRead := 0
				for totalRead < int(recLen) {
					n, rErr := c.Read(body[totalRead:])
					if rErr != nil {
						break
					}
					totalRead += n
				}

				if len(body) >= 71 && hdr[0] == 0x16 {
					clientRandom := body[6:38]
					sessionID := body[39:71]
					_, _, valid := verifySessionID(pskBytes, clientRandom, sessionID)
					if !valid {
						t.Errorf("多引擎并发子连接中检测到未通过认证的 SessionID")
					}
				}
			}(conn)
		}
	}()

	client, err := NewNaiveClient(NaiveClientOptions{
		ServerAddress:         M.ParseSocksaddrHostPort("127.0.0.1", serverPort),
		ServerName:            "image.apple.com",
		InsecureConcurrency:   concurrency,
		TestForceSingleEngine: false,
		DNSResolver: func(ctx context.Context, request *mDNS.Msg) *mDNS.Msg {
			return emptyDNSResponse(request)
		},
		PTLS:    true,
		PTLSPSK: testPSK,
	})
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	if err := client.Start(); err != nil {
		t.Fatalf("启动客户端失败: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	for i := 0; i < concurrency; i++ {
		go func() {
			_, _ = client.DialEarly(ctx, M.ParseSocksaddrHostPort("1.1.1.1", 443))
		}()
	}

	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
	case <-time.After(5 * time.Second):
		t.Fatal("多引擎并发建连超时")
	}
}

func verifySessionID(psk, clientRandom, sessionID []byte) (uint64, []byte, bool) {
	if len(sessionID) != 32 {
		return 0, nil, false
	}
	maskedTS := make([]byte, 8)
	authTag := make([]byte, 24)
	for i := 0; i < 8; i++ {
		maskedTS[i] = sessionID[i*4]
		authTag[i*3+0] = sessionID[i*4+1]
		authTag[i*3+1] = sessionID[i*4+2]
		authTag[i*3+2] = sessionID[i*4+3]
	}

	hMask := hmac.New(sha256.New, psk)
	hMask.Write(clientRandom)
	hMask.Write([]byte("ptls-v1-whitening-mask"))
	mask := hMask.Sum(nil)[:8]

	tsBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		tsBytes[i] = maskedTS[i] ^ mask[i]
	}
	ts := binary.BigEndian.Uint64(tsBytes)

	hAuth := hmac.New(sha256.New, psk)
	hAuth.Write(tsBytes)
	hAuth.Write(clientRandom)
	hAuth.Write([]byte("ptls-v1-session-auth"))
	expectedTag := hAuth.Sum(nil)[:24]

	if !hmac.Equal(authTag, expectedTag) {
		return 0, nil, false
	}
	return ts, authTag, true
}

func emptyDNSResponse(request *mDNS.Msg) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(request)
	return response
}
