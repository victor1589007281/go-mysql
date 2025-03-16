package packet

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	goErrors "errors"
	"io"
	"net"
	"time"

	"github.com/go-mysql-org/go-mysql/compress"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/klauspost/compress/zstd"
	"github.com/pingcap/errors"
)

const (
	MinCompressionLength = 50
	DefaultBufferSize    = 16 * 1024
)

// Conn is the base class to handle MySQL protocol.
type Conn struct {
	net.Conn

	readTimeout  time.Duration
	writeTimeout time.Duration

	// Buffered reader for net.Conn in Non-TLS connection only to address replication performance issue.
	// See https://github.com/go-mysql-org/go-mysql/pull/422 for more details.
	br     *bufio.Reader
	reader io.Reader

	copyNBuf []byte

	header [4]byte

	Sequence uint8

	Compression uint8

	CompressedSequence uint8

	compressedHeader [7]byte

	compressedReader io.Reader

	compressedReaderActive bool
}

func NewConn(conn net.Conn) *Conn {
	return NewBufferedConn(conn, 65536) // 64kb
}

// NewBufferedConn 创建一个带缓冲区的连接
func NewBufferedConn(conn net.Conn, bufferSize int) *Conn {
	// 创建一个新的Conn对象
	c := new(Conn)
	// 设置底层网络连接
	c.Conn = conn

	// 创建带缓冲区的Reader，使用指定大小
	c.br = bufio.NewReaderSize(c, bufferSize)
	// 设置默认的reader为带缓冲区的reader
	c.reader = c.br

	// 创建默认大小的copyN缓冲区
	c.copyNBuf = make([]byte, DefaultBufferSize)

	// 返回配置好的连接对象
	return c
}

// NewConnWithTimeout 创建一个带超时设置的连接
func NewConnWithTimeout(conn net.Conn, readTimeout, writeTimeout time.Duration, bufferSize int) *Conn {
	// 创建一个带缓冲的连接
	c := NewBufferedConn(conn, bufferSize)
	// 设置读取超时时间
	c.readTimeout = readTimeout
	// 设置写入超时时间
	c.writeTimeout = writeTimeout
	// 返回配置好的连接对象
	return c
}

func NewTLSConn(conn net.Conn) *Conn {
	c := new(Conn)
	c.Conn = conn

	c.reader = c

	c.copyNBuf = make([]byte, DefaultBufferSize)

	return c
}

func NewTLSConnWithTimeout(conn net.Conn, readTimeout, writeTimeout time.Duration) *Conn {
	c := NewTLSConn(conn)
	c.readTimeout = readTimeout
	c.writeTimeout = writeTimeout
	return c
}

// ReadPacket 读取一个MySQL协议包
func (c *Conn) ReadPacket() ([]byte, error) {
	return c.ReadPacketReuseMem(nil)
}

// ReadPacketReuseMem 读取一个MySQL协议包并复用内存
func (c *Conn) ReadPacketReuseMem(dst []byte) ([]byte, error) {
	// Here we use `sync.Pool` to avoid allocate/destroy buffers frequently.
	// 这里我们使用`sync.Pool`来避免频繁分配/销毁缓冲区
	buf := utils.BytesBufferGet()
	defer func() {
		utils.BytesBufferPut(buf)
	}()

	// 如果启用了压缩
	if c.Compression != mysql.MYSQL_COMPRESS_NONE {
		// it's possible that we're using compression but the server response with a compressed
		// packet with uncompressed length of 0. In this case we leave compressedReader nil. The
		// compressedReaderActive flag is important to track the state of the reader, allowing
		// for the compressedReader to be reset after a packet write. Without this flag, when a
		// compressed packet with uncompressed length of 0 is read, the compressedReader would
		// be nil, and we'd incorrectly attempt to read the next packet as compressed.
		// 有可能我们使用了压缩但服务器返回了一个解压长度为0的压缩包。在这种情况下我们保持compressedReader为nil。
		// compressedReaderActive标志对于跟踪读取器的状态很重要，允许在数据包写入后重置compressedReader。
		// 如果没有这个标志，当读取到一个解压长度为0的压缩包时，compressedReader将为nil，
		// 我们会错误地尝试将下一个数据包作为压缩数据包读取。
		if !c.compressedReaderActive {
			var err error
			c.compressedReader, err = c.newCompressedPacketReader()
			if err != nil {
				return nil, err
			}
			c.compressedReaderActive = true
		}
	}

	// 将数据包读取到缓冲区
	if err := c.ReadPacketTo(buf); err != nil {
		return nil, errors.Trace(err)
	}

	// 获取读取的字节和大小
	readBytes := buf.Bytes()
	readSize := len(readBytes)
	var result []byte

	// 如果提供了目标缓冲区
	if len(dst) > 0 {
		result = append(dst, readBytes...)
		// 如果读取的块太大，不再缓存缓冲区
		// if read block is big, do not cache buf anymore
		if readSize > utils.TooBigBlockSize {
			buf = nil
		}
	} else {
		if readSize > utils.TooBigBlockSize {
			// 如果读取的块太大，直接使用读取的块作为结果并不再缓存缓冲区
			// if read block is big, use read block as result and do not cache buf anymore
			result = readBytes
			buf = nil
		} else {
			result = append(dst, readBytes...)
		}
	}

	return result, nil
}

// newCompressedPacketReader creates a new compressed packet reader.
func (c *Conn) newCompressedPacketReader() (io.Reader, error) {
	if c.readTimeout != 0 {
		if err := c.SetReadDeadline(utils.Now().Add(c.readTimeout)); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(c.reader, c.compressedHeader[:7]); err != nil {
		return nil, errors.Wrapf(mysql.ErrBadConn, "io.ReadFull(compressedHeader) failed. err %v", err)
	}

	compressedSequence := c.compressedHeader[3]
	if compressedSequence != c.CompressedSequence {
		return nil, errors.Errorf("invalid compressed sequence %d != %d",
			compressedSequence, c.CompressedSequence)
	}

	compressedLength := int(uint32(c.compressedHeader[0]) | uint32(c.compressedHeader[1])<<8 | uint32(c.compressedHeader[2])<<16)
	uncompressedLength := int(uint32(c.compressedHeader[4]) | uint32(c.compressedHeader[5])<<8 | uint32(c.compressedHeader[6])<<16)
	if uncompressedLength > 0 {
		limitedReader := io.LimitReader(c.reader, int64(compressedLength))
		switch c.Compression {
		case mysql.MYSQL_COMPRESS_ZLIB:
			return compress.GetPooledZlibReader(limitedReader)
		case mysql.MYSQL_COMPRESS_ZSTD:
			return zstd.NewReader(limitedReader)
		}
	}

	return nil, nil
}

func (c *Conn) currentPacketReader() io.Reader {
	if c.Compression == mysql.MYSQL_COMPRESS_NONE || c.compressedReader == nil {
		return c.reader
	} else {
		return c.compressedReader
	}
}

func (c *Conn) copyN(dst io.Writer, n int64) (int64, error) {
	var written int64

	for n > 0 {
		bcap := cap(c.copyNBuf)
		if int64(bcap) > n {
			bcap = int(n)
		}
		buf := c.copyNBuf[:bcap]

		// Call ReadAtLeast with the currentPacketReader as it may change on every iteration
		// of this loop.
		if c.readTimeout != 0 {
			if err := c.SetReadDeadline(utils.Now().Add(c.readTimeout)); err != nil {
				return written, err
			}
		}
		rd, err := io.ReadAtLeast(c.currentPacketReader(), buf, bcap)

		n -= int64(rd)

		// ReadAtLeast will return EOF or ErrUnexpectedEOF when fewer than the min
		// bytes are read. In this case, and when we have compression then advance
		// the sequence number and reset the compressed reader to continue reading
		// the remaining bytes in the next compressed packet.
		if c.Compression != mysql.MYSQL_COMPRESS_NONE &&
			(goErrors.Is(err, io.ErrUnexpectedEOF) || goErrors.Is(err, io.EOF)) {
			// we have read to EOF and read an incomplete uncompressed packet
			// so advance the compressed sequence number and reset the compressed reader
			// to get the remaining unread uncompressed bytes from the next compressed packet.
			c.CompressedSequence++
			if c.compressedReader, err = c.newCompressedPacketReader(); err != nil {
				return written, errors.Trace(err)
			}
		}

		if err != nil {
			return written, errors.Trace(err)
		}

		// careful to only write from the buffer the number of bytes read
		wr, err := dst.Write(buf[:rd])
		written += int64(wr)
		if err != nil {
			return written, errors.Trace(err)
		}
	}

	return written, nil
}

func (c *Conn) ReadPacketTo(w io.Writer) error {
	b := utils.BytesBufferGet()
	defer func() {
		utils.BytesBufferPut(b)
	}()

	// packets that come in a compressed packet may be partial
	// so use the copyN function to read the packet header into a
	// buffer, since copyN is capable of getting the next compressed
	// packet and updating the Conn state with a new compressedReader.
	if _, err := c.copyN(b, 4); err != nil {
		return errors.Wrapf(mysql.ErrBadConn, "io.ReadFull(header) failed. err %v", err)
	} else {
		// copy was successful so copy the 4 bytes from the buffer to the header
		copy(c.header[:4], b.Bytes()[:4])
	}

	length := int(uint32(c.header[0]) | uint32(c.header[1])<<8 | uint32(c.header[2])<<16)
	sequence := c.header[3]

	if sequence != c.Sequence {
		return errors.Errorf("invalid sequence %d != %d", sequence, c.Sequence)
	}

	c.Sequence++

	if buf, ok := w.(*bytes.Buffer); ok {
		// Allocate the buffer with expected length directly instead of call `grow` and migrate data many times.
		buf.Grow(length)
	}

	if n, err := c.copyN(w, int64(length)); err != nil {
		return errors.Wrapf(mysql.ErrBadConn, "io.CopyN failed. err %v, copied %v, expected %v", err, n, length)
	} else if n != int64(length) {
		return errors.Wrapf(mysql.ErrBadConn, "io.CopyN failed(n != int64(length)). %v bytes copied, while %v expected", n, length)
	} else {
		if length < mysql.MaxPayloadLen {
			return nil
		}

		if err = c.ReadPacketTo(w); err != nil {
			return errors.Wrap(err, "ReadPacketTo failed")
		}
	}

	return nil
}

// WritePacket data already has 4 bytes header will modify data in-place
// WritePacket 方法用于写入数据包，数据已经包含4字节头部，会就地修改数据
func (c *Conn) WritePacket(data []byte) error {
	// 计算实际数据长度（减去4字节头部）
	length := len(data) - 4

	// 处理大于最大负载长度的数据包（分片发送）
	for length >= mysql.MaxPayloadLen {
		// 设置分片数据包头部
		data[0] = 0xff
		data[1] = 0xff
		data[2] = 0xff

		// 设置序列号
		data[3] = c.Sequence

		// 写入分片数据包
		if n, err := c.writeWithTimeout(data[:4+mysql.MaxPayloadLen]); err != nil {
			return errors.Wrapf(mysql.ErrBadConn,
				"Write(payload portion) failed. err %v", err)
		} else if n != (4 + mysql.MaxPayloadLen) {
			return errors.Wrapf(mysql.ErrBadConn,
				"Write(payload portion) failed. only %v bytes written, while %v expected", n, 4+mysql.MaxPayloadLen)
		} else {
			// 成功写入后递增序列号并更新剩余数据
			c.Sequence++
			length -= mysql.MaxPayloadLen
			data = data[mysql.MaxPayloadLen:]
		}
	}

	// 设置最后一个数据包的头部信息
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = c.Sequence

	// 根据压缩设置选择不同的写入方式
	switch c.Compression {
	case mysql.MYSQL_COMPRESS_NONE:
		// 无压缩模式直接写入
		if n, err := c.writeWithTimeout(data); err != nil {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. err %v", err)
		} else if n != len(data) {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. only %v bytes written, while %v expected", n, len(data))
		}
	case mysql.MYSQL_COMPRESS_ZLIB, mysql.MYSQL_COMPRESS_ZSTD:
		// 压缩模式写入
		if n, err := c.writeCompressed(data); err != nil {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. err %v", err)
		} else if n != len(data) {
			return errors.Wrapf(mysql.ErrBadConn, "Write failed. only %v bytes written, while %v expected", n, len(data))
		}

		// 重置压缩读取器状态
		c.compressedReaderActive = false
		if c.compressedReader != nil {
			if _, ok := c.compressedReader.(io.ReadCloser); ok {
				_ = c.compressedReader.(io.ReadCloser).Close()
			}
			c.compressedReader = nil
		}
	default:
		return errors.Wrapf(mysql.ErrBadConn, "Write failed. Unsuppored compression algorithm set")
	}

	// 递增序列号并返回
	c.Sequence++
	return nil
}

// writeWithTimeout 带超时的写入方法
func (c *Conn) writeWithTimeout(b []byte) (n int, err error) {
	// 如果设置了写超时
	if c.writeTimeout != 0 {
		// 设置写操作的截止时间
		if err := c.SetWriteDeadline(utils.Now().Add(c.writeTimeout)); err != nil {
			return n, err
		}
	}

	// 执行实际的写操作
	return c.Write(b)
}

func (c *Conn) writeCompressed(data []byte) (n int, err error) {
	var (
		compressedLength, uncompressedLength int
		payload                              *bytes.Buffer
		compressedHeader                     [7]byte
	)

	if len(data) > MinCompressionLength {
		var w io.WriteCloser
		payload = utils.BytesBufferGet()
		defer utils.BytesBufferPut(payload)

		switch c.Compression {
		case mysql.MYSQL_COMPRESS_ZLIB:
			w, err = compress.GetPooledZlibWriter(payload)
		case mysql.MYSQL_COMPRESS_ZSTD:
			w, err = zstd.NewWriter(payload)
		default:
			return 0, errors.Wrapf(mysql.ErrBadConn, "Write failed. Unsuppored compression algorithm set")
		}
		if err != nil {
			return 0, err
		}

		uncompressedLength = len(data)
		if n, err = w.Write(data); err != nil {
			_ = w.Close()
			return 0, err
		}
		if err = w.Close(); err != nil {
			return 0, err
		}

		compressedLength = payload.Len()
	} else {
		compressedLength = len(data)
	}

	c.CompressedSequence = 0
	// write the compressed packet header
	compressedPacket := utils.BytesBufferGet()
	defer utils.BytesBufferPut(compressedPacket)

	compressedHeader[0] = byte(compressedLength)
	compressedHeader[1] = byte(compressedLength >> 8)
	compressedHeader[2] = byte(compressedLength >> 16)
	compressedHeader[3] = c.CompressedSequence
	compressedHeader[4] = byte(uncompressedLength)
	compressedHeader[5] = byte(uncompressedLength >> 8)
	compressedHeader[6] = byte(uncompressedLength >> 16)
	if _, err = compressedPacket.Write(compressedHeader[:]); err != nil {
		return 0, err
	}
	c.CompressedSequence++

	if payload != nil {
		_, err = compressedPacket.Write(payload.Bytes())
	} else {
		n, err = compressedPacket.Write(data)
	}

	if err != nil {
		return 0, err
	}
	if _, err = c.writeWithTimeout(compressedPacket.Bytes()); err != nil {
		return 0, err
	}

	return n, nil
}

// WriteClearAuthPacket Client clear text authentication packet
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
func (c *Conn) WriteClearAuthPacket(password string) error {
	// Calculate the packet length and add a tailing 0
	pktLen := len(password) + 1
	data := make([]byte, 4+pktLen)

	// Add the clear password [null terminated string]
	copy(data[4:], password)
	data[4+pktLen-1] = 0x00

	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

// WritePublicKeyAuthPacket Caching sha2 authentication. Public key request and send encrypted password
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
func (c *Conn) WritePublicKeyAuthPacket(password string, cipher []byte) error {
	// request public key
	data := make([]byte, 4+1)
	data[4] = 2 // cachingSha2PasswordRequestPublicKey
	if err := c.WritePacket(data); err != nil {
		return errors.Wrap(err, "WritePacket(single byte) failed")
	}

	data, err := c.ReadPacket()
	if err != nil {
		return errors.Wrap(err, "ReadPacket failed")
	}

	block, _ := pem.Decode(data[1:])
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "x509.ParsePKIXPublicKey failed")
	}

	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(cipher)
		plain[i] ^= cipher[j]
	}
	sha1v := sha1.New()
	enc, _ := rsa.EncryptOAEP(sha1v, rand.Reader, pub.(*rsa.PublicKey), plain, nil)
	data = make([]byte, 4+len(enc))
	copy(data[4:], enc)
	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

func (c *Conn) WriteEncryptedPassword(password string, seed []byte, pub *rsa.PublicKey) error {
	enc, err := mysql.EncryptPassword(password, seed, pub)
	if err != nil {
		return errors.Wrap(err, "EncryptPassword failed")
	}
	return errors.Wrap(c.WriteAuthSwitchPacket(enc, false), "WriteAuthSwitchPacket failed")
}

// WriteAuthSwitchPacket see https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_response.html
// 写入认证切换包，参考MySQL协议文档
func (c *Conn) WriteAuthSwitchPacket(authData []byte, addNUL bool) error {
	// 计算包长度（4字节头部 + 认证数据长度）
	pktLen := 4 + len(authData)
	// 如果需要添加NUL终止符，增加长度
	if addNUL {
		pktLen++
	}
	// 创建数据缓冲区
	data := make([]byte, pktLen)

	// Add the auth data [EOF]
	// 添加认证数据 [EOF]
	copy(data[4:], authData)
	// 如果需要，添加NUL终止符
	if addNUL {
		data[pktLen-1] = 0x00
	}

	// 写入数据包并返回结果
	return errors.Wrap(c.WritePacket(data), "WritePacket failed")
}

// ResetSequence 重置序列号
func (c *Conn) ResetSequence() {
	c.Sequence = 0
}

// Close 关闭连接
func (c *Conn) Close() error {
	// 重置序列号
	c.Sequence = 0
	// 如果连接存在，关闭连接
	if c.Conn != nil {
		return errors.Wrap(c.Conn.Close(), "Conn.Close failed")
	}
	return nil
}
