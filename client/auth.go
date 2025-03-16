package client

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser/charset"
)

const defaultAuthPluginName = mysql.AUTH_NATIVE_PASSWORD

// defines the supported auth plugins
var supportedAuthPlugins = []string{mysql.AUTH_NATIVE_PASSWORD, mysql.AUTH_SHA256_PASSWORD, mysql.AUTH_CACHING_SHA2_PASSWORD, mysql.AUTH_MARIADB_ED25519}

// helper function to determine what auth methods are allowed by this client
func authPluginAllowed(pluginName string) bool {
	for _, p := range supportedAuthPlugins {
		if pluginName == p {
			return true
		}
	}
	return false
}

// See:
//   - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
//   - https://github.com/alibaba/canal/blob/0ec46991499a22870dde4ae736b2586cbcbfea94/driver/src/main/java/com/alibaba/otter/canal/parse/driver/mysql/packets/server/HandshakeInitializationPacket.java#L89
//   - https://github.com/vapor/mysql-nio/blob/main/Sources/MySQLNIO/Protocol/MySQLProtocol%2BHandshakeV10.swift
//   - https://github.com/github/vitess-gh/blob/70ae1a2b3a116ff6411b0f40852d6e71382f6e07/go/mysql/client.go
func (c *Conn) readInitialHandshake() error {
	// 读取初始握手包
	data, err := c.ReadPacket()
	if err != nil {
		return errors.Trace(err)
	}

	// 检查是否是错误包
	if data[0] == mysql.ERR_HEADER {
		return errors.Annotate(c.handleErrorPacket(data), "read initial handshake error")
	}

	// 检查协议版本
	if data[0] != mysql.ClassicProtocolVersion {
		if data[0] == mysql.XProtocolVersion {
			return errors.Errorf(
				"invalid protocol version %d, expected 10. "+
					"This might be X Protocol, make sure to connect to the right port",
				data[0])
		}
		return errors.Errorf("invalid protocol version %d, expected 10", data[0])
	}
	pos := 1

	// skip mysql version
	// mysql version end with 0x00
	// 解析MySQL版本号
	version := data[pos : bytes.IndexByte(data[pos:], 0x00)+1]
	c.serverVersion = string(version)
	pos += len(version) + 1 /*trailing zero byte*/

	// connection id length is 4
	// 解析连接ID
	c.connectionID = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4

	// first 8 bytes of the plugin provided data (scramble)
	// 解析前8字节的认证数据（scramble）
	c.salt = append(c.salt[:0], data[pos:pos+8]...)
	pos += 8

	// 检查scramble后的终止符
	if data[pos] != 0 { // 	0x00 byte, terminating the first part of a scramble
		return errors.Errorf("expect 0x00 after scramble, got %q", rune(data[pos]))
	}
	pos++

	// The lower 2 bytes of the Capabilities Flags
	// 解析能力标志的低2字节
	c.capability = uint32(binary.LittleEndian.Uint16(data[pos : pos+2]))
	// check protocol
	// 检查协议支持情况
	if c.capability&mysql.CLIENT_PROTOCOL_41 == 0 {
		return errors.New("the MySQL server can not support protocol 41 and above required by the client")
	}
	// 检查SSL支持情况
	if c.capability&mysql.CLIENT_SSL == 0 && c.tlsConfig != nil {
		return errors.New("the MySQL Server does not support TLS required by the client")
	}
	pos += 2

	// 如果数据还有剩余
	if len(data) > pos {
		// default server a_protocol_character_set, only the lower 8-bits
		// c.charset = data[pos]
		pos += 1

		// 解析服务器状态
		c.status = binary.LittleEndian.Uint16(data[pos : pos+2])
		pos += 2

		// The upper 2 bytes of the Capabilities Flags
		// 解析能力标志的高2字节
		c.capability = uint32(binary.LittleEndian.Uint16(data[pos:pos+2]))<<16 | c.capability
		pos += 2

		// length of the combined auth_plugin_data (scramble), if auth_plugin_data_len is > 0
		// 解析认证插件数据长度
		authPluginDataLen := data[pos]
		if (c.capability&mysql.CLIENT_PLUGIN_AUTH == 0) && (authPluginDataLen > 0) {
			return errors.Errorf("invalid auth plugin data filler %d", authPluginDataLen)
		}
		pos++

		// skip reserved (all [00] ?)
		// 跳过保留字段
		pos += 10

		// 如果支持安全连接
		if c.capability&mysql.CLIENT_SECURE_CONNECTION != 0 {
			// Rest of the plugin provided data (scramble)

			// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
			// $len=MAX(13, length of auth-plugin-data - 8)
			//
			// https://github.com/mysql/mysql-server/blob/1bfe02bdad6604d54913c62614bde57a055c8332/sql/auth/sql_authentication.cc#L1641-L1642
			// the first packet *must* have at least 20 bytes of a scramble.
			// if a plugin provided less, we pad it to 20 with zeros
			// 计算剩余的认证数据长度
			rest := int(authPluginDataLen) - 8
			if rest < 13 {
				rest = 13
			}

			// 获取剩余的认证数据
			authPluginDataPart2 := data[pos : pos+rest-1]
			pos += rest

			// 合并认证数据
			c.salt = append(c.salt, authPluginDataPart2...)
		}

		// 如果支持插件认证
		if c.capability&mysql.CLIENT_PLUGIN_AUTH != 0 {
			// 解析认证插件名称
			c.authPluginName = string(data[pos : pos+bytes.IndexByte(data[pos:], 0x00)])
			pos += len(c.authPluginName)

			// 检查认证插件名称后的终止符
			if data[pos] != 0 {
				return errors.Errorf("expect 0x00 after authPluginName, got %q", rune(data[pos]))
			}
			// pos++ // ineffectual
		}
	}

	// if server gives no default auth plugin name, use a client default
	if c.authPluginName == "" {
		c.authPluginName = defaultAuthPluginName
	}

	return nil
}

// generate auth response data according to auth plugin
// 根据认证插件生成认证响应数据
//
// NOTE: the returned boolean value indicates whether to add a \NUL to the end of data.
// it is quite tricky because MySQL server expects different formats of responses in different auth situations.
// here the \NUL needs to be added when sending back the empty password or cleartext password in 'sha256_password'
// authentication.
// 注意：返回的布尔值表示是否在数据末尾添加\NUL
// 这很棘手，因为MySQL服务器在不同认证情况下期望不同的响应格式
// 在'sha256_password'认证中发送空密码或明文密码时需要添加\NUL
func (c *Conn) genAuthResponse(authData []byte) ([]byte, bool, error) {
	// password hashing
	// 密码哈希处理
	switch c.authPluginName {
	case mysql.AUTH_NATIVE_PASSWORD:
		// 原生密码认证
		return mysql.CalcPassword(authData[:20], []byte(c.password)), false, nil
	case mysql.AUTH_CACHING_SHA2_PASSWORD:
		// 缓存SHA2密码认证
		return mysql.CalcCachingSha2Password(authData, c.password), false, nil
	case mysql.AUTH_CLEAR_PASSWORD:
		// 明文密码认证
		return []byte(c.password), true, nil
	case mysql.AUTH_SHA256_PASSWORD:
		// SHA256密码认证
		if len(c.password) == 0 {
			// 空密码情况
			return nil, true, nil
		}
		if c.tlsConfig != nil || c.proto == "unix" {
			// write cleartext auth packet
			// see: https://dev.mysql.com/doc/refman/8.0/en/sha256-pluggable-authentication.html
			// 如果使用TLS或unix socket，发送明文认证包
			return []byte(c.password), true, nil
		} else {
			// request public key from server
			// see: https://dev.mysql.com/doc/internals/en/public-key-retrieval.html
			// 否则请求服务器公钥
			return []byte{1}, false, nil
		}
	case mysql.AUTH_MARIADB_ED25519:
		// MariaDB ED25519认证
		if len(authData) != 32 {
			return nil, false, mysql.ErrMalformPacket
		}
		res, err := mysql.CalcEd25519Password(authData, c.password)
		if err != nil {
			return nil, false, err
		}
		return res, false, nil
	default:
		// not reachable
		// 默认情况（理论上不会到达）
		return nil, false, fmt.Errorf("auth plugin '%s' is not supported", c.authPluginName)
	}
}

// generate connection attributes data
func (c *Conn) genAttributes() []byte {
	if len(c.attributes) == 0 {
		return nil
	}

	attrData := make([]byte, 0)
	for k, v := range c.attributes {
		attrData = append(attrData, mysql.PutLengthEncodedString([]byte(k))...)
		attrData = append(attrData, mysql.PutLengthEncodedString([]byte(v))...)
	}
	return append(mysql.PutLengthEncodedInt(uint64(len(attrData))), attrData...)
}

// See: http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
// 处理握手响应包
func (c *Conn) writeAuthHandshake() error {
	// 检查认证插件是否被允许
	if !authPluginAllowed(c.authPluginName) {
		return fmt.Errorf("unknown auth plugin name '%s'", c.authPluginName)
	}

	// Set default client capabilities that reflect the abilities of this library
	// 设置默认的客户端能力标志
	capability := mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION |
		mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_PLUGIN_AUTH
	// Adjust client capability flags based on server support
	capability |= c.capability & mysql.CLIENT_LONG_FLAG
	capability |= c.capability & mysql.CLIENT_QUERY_ATTRIBUTES
	// Adjust client capability flags on specific client requests
	// Only flags that would make any sense setting and aren't handled elsewhere
	// in the library are supported here
	capability |= c.ccaps&mysql.CLIENT_FOUND_ROWS | c.ccaps&mysql.CLIENT_IGNORE_SPACE |
		c.ccaps&mysql.CLIENT_MULTI_STATEMENTS | c.ccaps&mysql.CLIENT_MULTI_RESULTS |
		c.ccaps&mysql.CLIENT_PS_MULTI_RESULTS | c.ccaps&mysql.CLIENT_CONNECT_ATTRS |
		c.ccaps&mysql.CLIENT_COMPRESS | c.ccaps&mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM |
		c.ccaps&mysql.CLIENT_LOCAL_FILES

	// To enable TLS / SSL
	// 如果配置了TLS，添加SSL支持能力
	if c.tlsConfig != nil {
		capability |= mysql.CLIENT_SSL
	}

	// 生成认证响应
	auth, addNull, err := c.genAuthResponse(c.salt)
	if err != nil {
		return err
	}

	// encode length of the auth plugin data
	// here we use the Length-Encoded-Integer(LEI) as the data length may not fit into one byte
	// see: https://dev.mysql.com/doc/internals/en/integer.html#length-encoded-integer
	// 使用长度编码整数(LEI)编码认证数据的长度
	var authRespLEIBuf [9]byte
	authRespLEI := mysql.AppendLengthEncodedInteger(authRespLEIBuf[:0], uint64(len(auth)))
	if len(authRespLEI) > 1 {
		// if the length can not be written in 1 byte, it must be written as a
		// length encoded integer
		// 如果长度无法用1字节表示，则必须使用长度编码整数
		capability |= mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	}

	// packet length
	// capability 4
	// max-packet size 4
	// charset 1
	// reserved all[0] 23
	// username
	// auth
	// mysql_native_password + null-terminated
	// 计算数据包长度
	length := 4 + 4 + 1 + 23 + len(c.user) + 1 + len(authRespLEI) + len(auth) + 21 + 1
	if addNull {
		length++
	}

	// db name
	// 如果指定了数据库名称，添加相关能力标志
	if len(c.db) > 0 {
		capability |= mysql.CLIENT_CONNECT_WITH_DB
		length += len(c.db) + 1
	}

	// connection attributes
	// 生成连接属性数据
	attrData := c.genAttributes()
	if len(attrData) > 0 {
		capability |= mysql.CLIENT_CONNECT_ATTRS
		length += len(attrData)
	}

	// 如果启用了ZSTD压缩算法，增加长度
	if c.ccaps&mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM > 0 {
		length++
	}

	// 创建数据缓冲区
	data := make([]byte, length+4)

	// capability [32 bit]
	// 写入能力标志 [32位]
	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)

	// MaxPacketSize [32 bit] (none)
	// 写入最大数据包大小 [32位] (默认0)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Charset [1 byte]
	// use default collation id 255 here, is `utf8mb4_0900_ai_ci`
	// 获取字符集
	collationName := c.collation
	if len(collationName) == 0 {
		collationName = mysql.DEFAULT_COLLATION_NAME
	}
	collation, err := charset.GetCollationByName(collationName)
	if err != nil {
		return fmt.Errorf("invalid collation name %s", collationName)
	}

	// the MySQL protocol calls for the collation id to be sent as 1 byte, where only the
	// lower 8 bits are used in this field.
	// 写入字符集ID [1字节]
	data[12] = byte(collation.ID & 0xff)

	// SSL Connection Request Packet
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	// 如果配置了TLS，处理SSL连接
	if c.tlsConfig != nil {
		// 发送SSL请求包
		// Send TLS / SSL request packet
		if err := c.WritePacket(data[:(4+4+1+23)+4]); err != nil {
			return err
		}

		// 切换到TLS连接
		// Switch to TLS
		tlsConn := tls.Client(c.Conn.Conn, c.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}

		// 更新连接对象
		currentSequence := c.Sequence
		c.Conn = packet.NewConnWithTimeout(tlsConn, c.ReadTimeout, c.WriteTimeout, c.BufferSize)
		c.Sequence = currentSequence
	}

	// 填充23字节的保留字段
	// Filler [23 bytes] (all 0x00)
	pos := 13
	for ; pos < 13+23; pos++ {
		data[pos] = 0
	}

	// 写入用户名 [以null结尾的字符串]
	// User [null terminated string]
	if len(c.user) > 0 {
		pos += copy(data[pos:], c.user)
	}
	data[pos] = 0x00
	pos++

	// 写入认证数据 [长度编码整数]
	// auth [length encoded integer]
	pos += copy(data[pos:], authRespLEI)
	pos += copy(data[pos:], auth)
	if addNull {
		data[pos] = 0x00
		pos++
	}

	// 写入数据库名称 [以null结尾的字符串]
	// db [null terminated string]
	if len(c.db) > 0 {
		pos += copy(data[pos:], c.db)
		data[pos] = 0x00
		pos++
	}

	// Assume native client during response
	// 假设在响应期间使用原生客户端
	pos += copy(data[pos:], c.authPluginName) // 复制认证插件名称到数据缓冲区
	data[pos] = 0x00                          // 添加null终止符
	pos++                                     // 移动位置指针

	// connection attributes
	// 连接属性
	if len(attrData) > 0 {
		// 如果有连接属性数据
		pos += copy(data[pos:], attrData) // 将连接属性数据复制到数据缓冲区
	}

	if c.ccaps&mysql.CLIENT_ZSTD_COMPRESSION_ALGORITHM > 0 {
		// zstd_compression_level
		// 如果启用了ZSTD压缩算法
		data[pos] = 0x03 // 设置ZSTD压缩级别为3
	}

	return c.WritePacket(data)
}
