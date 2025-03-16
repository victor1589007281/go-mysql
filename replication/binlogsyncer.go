package replication

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pingcap/errors"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/utils"
)

var errSyncRunning = errors.New("Sync is running, must Close first")

// BinlogSyncerConfig is the configuration for BinlogSyncer.
type BinlogSyncerConfig struct {
	// ServerID is the unique ID in cluster.
	ServerID uint32
	// Flavor is "mysql" or "mariadb", if not set, use "mysql" default.
	Flavor string

	// Host is for MySQL server host.
	Host string
	// Port is for MySQL server port.
	Port uint16
	// User is for MySQL user.
	User string
	// Password is for MySQL password.
	Password string

	// Localhost is local hostname if register salve.
	// If not set, use os.Hostname() instead.
	Localhost string

	// Charset is for MySQL client character set
	Charset string

	// SemiSyncEnabled enables semi-sync or not.
	SemiSyncEnabled bool

	// RawModeEnabled is for not parsing binlog event.
	RawModeEnabled bool

	// If not nil, use the provided tls.Config to connect to the database using TLS/SSL.
	TLSConfig *tls.Config

	// Use replication.Time structure for timestamp and datetime.
	// We will use Local location for timestamp and UTC location for datetime.
	ParseTime bool

	// If ParseTime is false, convert TIMESTAMP into this specified timezone. If
	// ParseTime is true, this option will have no effect and TIMESTAMP data will
	// be parsed into the local timezone and a full time.Time struct will be
	// returned.
	//
	// Note that MySQL TIMESTAMP columns are offset from the machine local
	// timezone while DATETIME columns are offset from UTC. This is consistent
	// with documented MySQL behaviour as it return TIMESTAMP in local timezone
	// and DATETIME in UTC.
	//
	// Setting this to UTC effectively equalizes the TIMESTAMP and DATETIME time
	// strings obtained from MySQL.
	TimestampStringLocation *time.Location

	// Use decimal.Decimal structure for decimals.
	UseDecimal bool

	// RecvBufferSize sets the size in bytes of the operating system's receive buffer associated with the connection.
	RecvBufferSize int

	// master heartbeat period
	HeartbeatPeriod time.Duration

	// read timeout
	ReadTimeout time.Duration

	// maximum number of attempts to re-establish a broken connection, zero or negative number means infinite retry.
	// this configuration will not work if DisableRetrySync is true
	MaxReconnectAttempts int

	// whether disable re-sync for broken connection
	DisableRetrySync bool

	// Only works when MySQL/MariaDB variable binlog_checksum=CRC32.
	// For MySQL, binlog_checksum was introduced since 5.6.2, but CRC32 was set as default value since 5.6.6 .
	// https://dev.mysql.com/doc/refman/5.6/en/replication-options-binary-log.html#option_mysqld_binlog-checksum
	// For MariaDB, binlog_checksum was introduced since MariaDB 5.3, but CRC32 was set as default value since MariaDB 10.2.1 .
	// https://mariadb.com/kb/en/library/replication-and-binary-log-server-system-variables/#binlog_checksum
	VerifyChecksum bool

	// DumpCommandFlag is used to send binglog dump command. Default 0, aka BINLOG_DUMP_NEVER_STOP.
	// For MySQL, BINLOG_DUMP_NEVER_STOP and BINLOG_DUMP_NON_BLOCK are available.
	// https://dev.mysql.com/doc/internals/en/com-binlog-dump.html#binlog-dump-non-block
	// For MariaDB, BINLOG_DUMP_NEVER_STOP, BINLOG_DUMP_NON_BLOCK and BINLOG_SEND_ANNOTATE_ROWS_EVENT are available.
	// https://mariadb.com/kb/en/library/com_binlog_dump/
	// https://mariadb.com/kb/en/library/annotate_rows_event/
	DumpCommandFlag uint16

	// Option function is used to set outside of BinlogSyncerConfig， between mysql connection and COM_REGISTER_SLAVE
	// For MariaDB: slave_gtid_ignore_duplicates、skip_replication、slave_until_gtid
	Option func(*client.Conn) error

	// Set Logger
	Logger *slog.Logger

	// Set Dialer
	Dialer client.Dialer

	RowsEventDecodeFunc func(*RowsEvent, []byte) error

	TableMapOptionalMetaDecodeFunc func([]byte) error

	DiscardGTIDSet bool

	EventCacheCount int

	// SynchronousEventHandler is used for synchronous event handling.
	// This should not be used together with StartBackupWithHandler.
	// If this is not nil, GetEvent does not need to be called.
	SynchronousEventHandler EventHandler
}

// EventHandler defines the interface for processing binlog events.
type EventHandler interface {
	HandleEvent(e *BinlogEvent) error
}

// BinlogSyncer syncs binlog events from the server.
type BinlogSyncer struct {
	m sync.RWMutex

	cfg BinlogSyncerConfig

	c *client.Conn

	wg sync.WaitGroup

	parser *BinlogParser

	nextPos mysql.Position

	prevGset, currGset mysql.GTIDSet

	// instead of GTIDSet.Clone, use this to speed up calculate prevGset
	prevMySQLGTIDEvent *GTIDEvent

	running bool

	ctx    context.Context
	cancel context.CancelFunc

	lastConnectionID uint32

	retryCount int
}

// NewBinlogSyncer creates the BinlogSyncer with the given configuration.
func NewBinlogSyncer(cfg BinlogSyncerConfig) *BinlogSyncer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ServerID == 0 {
		cfg.Logger.Error("can't use 0 as the server ID, will panic")
		panic("can't use 0 as the server ID")
	}
	if cfg.Dialer == nil {
		dialer := &net.Dialer{}
		cfg.Dialer = dialer.DialContext
	}
	if cfg.EventCacheCount == 0 {
		cfg.EventCacheCount = 10240
	}

	// Clear the Password to avoid outputting it in logs.
	pass := cfg.Password
	cfg.Password = ""
	cfg.Logger.Info("create BinlogSyncer", slog.Any("config", cfg))
	cfg.Password = pass

	b := new(BinlogSyncer)

	b.cfg = cfg
	b.parser = NewBinlogParser()
	b.parser.SetFlavor(cfg.Flavor)
	b.parser.SetRawMode(b.cfg.RawModeEnabled)
	b.parser.SetParseTime(b.cfg.ParseTime)
	b.parser.SetTimestampStringLocation(b.cfg.TimestampStringLocation)
	b.parser.SetUseDecimal(b.cfg.UseDecimal)
	b.parser.SetVerifyChecksum(b.cfg.VerifyChecksum)
	b.parser.SetRowsEventDecodeFunc(b.cfg.RowsEventDecodeFunc)
	b.parser.SetTableMapOptionalMetaDecodeFunc(b.cfg.TableMapOptionalMetaDecodeFunc)
	b.running = false
	b.ctx, b.cancel = context.WithCancel(context.Background())

	return b
}

// Close closes the BinlogSyncer.
func (b *BinlogSyncer) Close() {
	b.m.Lock()
	defer b.m.Unlock()

	b.close()
}

func (b *BinlogSyncer) close() {
	if b.isClosed() {
		return
	}

	b.cfg.Logger.Info("syncer is closing...")

	b.running = false
	b.cancel()

	if b.c != nil {
		err := b.c.SetReadDeadline(utils.Now().Add(100 * time.Millisecond))
		if err != nil {
			b.cfg.Logger.Warn("could not set read deadline", slog.Any("error", err))
		}
	}

	// kill last connection id
	if b.lastConnectionID > 0 {
		// Use a new connection to kill the binlog syncer
		// because calling KILL from the same connection
		// doesn't actually disconnect it.
		c, err := b.newConnection(context.Background())
		if err == nil {
			b.killConnection(c, b.lastConnectionID)
			c.Close()
		}
	}

	b.wg.Wait()

	if b.c != nil {
		b.c.Close()
	}

	b.cfg.Logger.Info("syncer is closed")
}

func (b *BinlogSyncer) isClosed() bool {
	select {
	case <-b.ctx.Done():
		return true
	default:
		return false
	}
}

// registerSlave 注册从库，建立与主库的连接并进行必要的配置
func (b *BinlogSyncer) registerSlave() error {
	// 如果已有连接则关闭
	if b.c != nil {
		b.c.Close()
	}

	// 创建新的数据库连接
	var err error
	b.c, err = b.newConnection(b.ctx)
	if err != nil {
		return errors.Trace(err)
	}

	// 执行自定义配置选项
	if b.cfg.Option != nil {
		if err = b.cfg.Option(b.c); err != nil {
			return errors.Trace(err)
		}
	}

	// 设置字符集
	if len(b.cfg.Charset) != 0 {
		if err = b.c.SetCharset(b.cfg.Charset); err != nil {
			return errors.Trace(err)
		}
	}

	// 设置读超时
	// set read timeout
	if b.cfg.ReadTimeout > 0 {
		_ = b.c.SetReadDeadline(utils.Now().Add(b.cfg.ReadTimeout))
	}

	// 设置接收缓冲区大小
	if b.cfg.RecvBufferSize > 0 {
		if tcp, ok := b.c.Conn.Conn.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(b.cfg.RecvBufferSize)
		}
	}

	// 如果存在上一个连接ID，则终止该连接
	// kill last connection id
	if b.lastConnectionID > 0 {
		b.killConnection(b.c, b.lastConnectionID)
	}

	// 保存当前连接ID
	// save last last connection id for kill
	b.lastConnectionID = b.c.GetConnectionID()

	// 检查并设置binlog校验和
	// for mysql 5.6+, binlog has a crc32 checksum
	// before mysql 5.6, this will not work, don't matter.:-)
	if r, err := b.c.Execute("SHOW GLOBAL VARIABLES LIKE 'BINLOG_CHECKSUM'"); err != nil {
		return errors.Trace(err)
	} else {
		s, _ := r.GetString(0, 1)
		if s != "" {
			// 设置binlog校验和为NONE
			// maybe CRC32 or NONE

			// mysqlbinlog.cc use NONE, see its below comments:
			// Make a notice to the server that this client
			// is checksum-aware. It does not need the first fake Rotate
			// necessary checksummed.
			// That preference is specified below.

			if _, err = b.c.Execute(`SET @master_binlog_checksum='NONE', @source_binlog_checksum='NONE'`); err != nil {
				return errors.Trace(err)
			}
		}
	}

	// 如果是MariaDB，设置GTID支持
	if b.cfg.Flavor == mysql.MariaDBFlavor {
		// Refer https://github.com/alibaba/canal/wiki/BinlogChange(MariaDB5&10)
		// Tell the server that we understand GTIDs by setting our slave capability
		// to MARIA_SLAVE_CAPABILITY_GTID = 4 (MariaDB >= 10.0.1).
		if _, err := b.c.Execute("SET @mariadb_slave_capability=4"); err != nil {
			return errors.Errorf("failed to set @mariadb_slave_capability=4: %v", err)
		}
	}

	// 设置心跳周期
	if b.cfg.HeartbeatPeriod > 0 {
		_, err = b.c.Execute(fmt.Sprintf("SET @master_heartbeat_period=%d;", b.cfg.HeartbeatPeriod))
		if err != nil {
			b.cfg.Logger.Error(fmt.Sprintf("failed to set @master_heartbeat_period=%d", b.cfg.HeartbeatPeriod), slog.Any("error", err))
			return errors.Trace(err)
		}
	}

	// 生成并设置从库UUID
	serverUUID, err := uuid.NewUUID()
	if err != nil {
		b.cfg.Logger.Error("failed to get new uuid", slog.Any("error", err))
		return errors.Trace(err)
	}
	if _, err = b.c.Execute(fmt.Sprintf("SET @slave_uuid = '%s', @replica_uuid = '%s'", serverUUID, serverUUID)); err != nil {
		b.cfg.Logger.Error(fmt.Sprintf("failed to set @slave_uuid = '%s', @replica_uuid = '%s'", serverUUID, serverUUID), slog.Any("error", err))
		return errors.Trace(err)
	}

	// 发送注册从库命令
	if err = b.writeRegisterSlaveCommand(); err != nil {
		return errors.Trace(err)
	}

	// 读取确认包
	if _, err = b.c.ReadOKPacket(); err != nil {
		return errors.Trace(err)
	}

	return nil
}

// enableSemiSync 启用半同步复制
func (b *BinlogSyncer) enableSemiSync() error {
	// 如果配置中未启用半同步复制，直接返回
	if !b.cfg.SemiSyncEnabled {
		return nil
	}

	// 查询主库是否启用了半同步复制
	if r, err := b.c.Execute("SHOW VARIABLES LIKE 'rpl_semi_sync_master_enabled';"); err != nil {
		return errors.Trace(err)
	} else {
		// 获取查询结果中的值
		s, _ := r.GetString(0, 1)
		// 如果主库不支持半同步复制
		if s != "ON" {
			// 记录错误日志并关闭半同步配置
			b.cfg.Logger.Error("master does not support semi synchronous replication, use no semi-sync")
			b.cfg.SemiSyncEnabled = false
			return nil
		}
	}

	// 设置从库的半同步复制参数
	_, err := b.c.Execute(`SET @rpl_semi_sync_slave = 1;`)
	if err != nil {
		return errors.Trace(err)
	}

	// 返回nil表示成功
	return nil
}

// prepare 准备binlog同步的初始化工作
func (b *BinlogSyncer) prepare() error {
	// 检查同步器是否已关闭
	if b.isClosed() {
		return errors.Trace(ErrSyncClosed)
	}

	// 注册从库
	if err := b.registerSlave(); err != nil {
		return errors.Trace(err)
	}

	// 启用半同步复制
	if err := b.enableSemiSync(); err != nil {
		return errors.Trace(err)
	}

	// 记录连接成功日志
	b.cfg.Logger.Info("Connected to server",
		slog.String("flavor", b.cfg.Flavor),
		slog.String("version", b.c.GetServerVersion()))

	// 返回nil表示准备成功
	return nil
}

func (b *BinlogSyncer) startDumpStream() *BinlogStreamer {
	// 设置运行状态为true
	b.running = true

	// 创建一个新的BinlogStreamer，使用配置的事件缓存大小
	s := NewBinlogStreamerWithChanSize(b.cfg.EventCacheCount)

	// 增加等待组计数器
	b.wg.Add(1)
	// 启动一个goroutine来处理binlog流
	go b.onStream(s)
	// 返回创建的BinlogStreamer
	return s
}

// GetNextPosition returns the next position of the syncer
func (b *BinlogSyncer) GetNextPosition() mysql.Position {
	return b.nextPos
}

func (b *BinlogSyncer) checkFlavor() {
	// 获取MySQL服务器版本
	serverVersion := b.c.GetServerVersion()
	// 如果配置的Flavor不是MariaDB，但服务器版本包含"MariaDB"
	if b.cfg.Flavor != mysql.MariaDBFlavor &&
		strings.Contains(serverVersion, "MariaDB") {
		// Setting the flavor to `mysql` causes MariaDB to try and behave
		// in a MySQL compatible way. In this mode MariaDB won't use
		// MariaDB specific binlog event types, but may used dummy events instead.
		// 将Flavor设置为`mysql`会导致MariaDB尝试以MySQL兼容的方式运行
		// 在这种模式下，MariaDB不会使用特定的binlog事件类型，而是可能使用虚拟事件
		b.cfg.Logger.Error("misconfigured flavor for server", slog.String("flavor", b.cfg.Flavor), slog.String("version", serverVersion))
	}
}

// StartSync starts syncing from the `pos` position.
func (b *BinlogSyncer) StartSync(pos mysql.Position) (*BinlogStreamer, error) {
	b.cfg.Logger.Info("begin to sync binlog from position", slog.Any("position", pos))

	b.m.Lock()
	defer b.m.Unlock()

	if b.running {
		return nil, errors.Trace(errSyncRunning)
	}

	if err := b.prepareSyncPos(pos); err != nil {
		return nil, errors.Trace(err)
	}

	b.checkFlavor()

	return b.startDumpStream(), nil
}

// StartSyncGTID starts syncing from the `gset` GTIDSet.
// StartSyncGTID 从指定的GTID集合开始同步binlog
func (b *BinlogSyncer) StartSyncGTID(gset mysql.GTIDSet) (*BinlogStreamer, error) {
	// 记录开始同步的日志信息
	b.cfg.Logger.Info("begin to sync binlog from GTID set", slog.Any("GTID set", gset))

	// 重置前一个MySQL GTID事件
	b.prevMySQLGTIDEvent = nil
	// 保存传入的GTID集合
	b.prevGset = gset

	// 加锁确保线程安全
	b.m.Lock()
	// 确保函数退出时解锁
	defer b.m.Unlock()

	// 检查是否已经在运行
	if b.running {
		// 如果已经在运行，返回错误
		return nil, errors.Trace(errSyncRunning)
	}

	// establishing network connection here and will start getting binlog events from "gset + 1", thus until first
	// MariadbGTIDEvent/GTIDEvent event is received - we effectively do not have a "current GTID"
	// 在这里建立网络连接，将从"gset + 1"开始获取binlog事件，
	// 因此在收到第一个MariadbGTIDEvent/GTIDEvent事件之前，我们没有"当前GTID"
	b.currGset = nil

	// 准备同步
	if err := b.prepare(); err != nil {
		// 如果准备失败返回错误
		return nil, errors.Trace(err)
	}

	// 根据数据库类型执行不同的命令
	var err error
	switch b.cfg.Flavor {
	case mysql.MariaDBFlavor:
		// 如果是MariaDB，写入MariaDB GTID dump命令
		err = b.writeBinlogDumpMariadbGTIDCommand(gset)
	default:
		// default use MySQL
		// 默认使用MySQL，写入MySQL GTID dump命令
		err = b.writeBinlogDumpMysqlGTIDCommand(gset)
	}

	// 检查命令执行是否成功
	if err != nil {
		// 如果失败返回错误
		return nil, err
	}

	// 检查数据库类型是否正确配置
	b.checkFlavor()

	// 启动dump流并返回
	return b.startDumpStream(), nil
}

func (b *BinlogSyncer) writeBinlogDumpCommand(p mysql.Position) error {
	// 重置连接序列号
	b.c.ResetSequence()

	// 创建数据包，包含固定头部和可变数据部分
	data := make([]byte, 4+1+4+2+4+len(p.Name))

	// 数据包起始位置（跳过4字节的头部）
	pos := 4
	// 设置命令类型为COM_BINLOG_DUMP
	data[pos] = mysql.COM_BINLOG_DUMP
	pos++

	// 写入binlog位置
	binary.LittleEndian.PutUint32(data[pos:], p.Pos)
	pos += 4

	// 写入dump命令标志位
	binary.LittleEndian.PutUint16(data[pos:], b.cfg.DumpCommandFlag)
	pos += 2

	// 写入服务器ID
	binary.LittleEndian.PutUint32(data[pos:], b.cfg.ServerID)
	pos += 4

	// 复制binlog文件名到数据包
	copy(data[pos:], p.Name)

	// 将数据包写入连接
	return b.c.WritePacket(data)
}

func (b *BinlogSyncer) writeBinlogDumpMysqlGTIDCommand(gset mysql.GTIDSet) error {
	// 创建一个默认的binlog位置，从位置4开始
	p := mysql.Position{Name: "", Pos: 4}
	// 将GTID集合编码为字节数组
	gtidData := gset.Encode()

	// 重置连接序列号
	b.c.ResetSequence()

	// 创建数据包，包含固定头部和可变数据部分
	data := make([]byte, 4+1+2+4+4+len(p.Name)+8+4+len(gtidData))
	// 数据包起始位置（跳过4字节的头部）
	pos := 4
	// 设置命令类型为COM_BINLOG_DUMP_GTID
	data[pos] = mysql.COM_BINLOG_DUMP_GTID
	pos++

	// 写入标志位（设置为0）
	binary.LittleEndian.PutUint16(data[pos:], 0)
	pos += 2

	// 写入服务器ID
	binary.LittleEndian.PutUint32(data[pos:], b.cfg.ServerID)
	pos += 4

	// 写入binlog文件名的长度
	binary.LittleEndian.PutUint32(data[pos:], uint32(len(p.Name)))
	pos += 4

	// 复制binlog文件名到数据包
	n := copy(data[pos:], p.Name)
	pos += n

	// 写入binlog位置
	binary.LittleEndian.PutUint64(data[pos:], uint64(p.Pos))
	pos += 8

	// 写入GTID数据的长度
	binary.LittleEndian.PutUint32(data[pos:], uint32(len(gtidData)))
	pos += 4
	// 复制GTID数据到数据包
	n = copy(data[pos:], gtidData)
	pos += n

	// 截取实际使用的数据部分
	data = data[0:pos]

	// 将数据包写入连接
	return b.c.WritePacket(data)
}

func (b *BinlogSyncer) writeBinlogDumpMariadbGTIDCommand(gset mysql.GTIDSet) error {
	// Copy from vitess

	startPos := gset.String()

	// Set the slave_connect_state variable before issuing COM_BINLOG_DUMP to
	// provide the start position in GTID form.
	query := fmt.Sprintf("SET @slave_connect_state='%s'", startPos)

	if _, err := b.c.Execute(query); err != nil {
		return errors.Errorf("failed to set @slave_connect_state='%s': %v", startPos, err)
	}

	// Real slaves set this upon connecting if their gtid_strict_mode option was
	// enabled. We always use gtid_strict_mode because we need it to make our
	// internal GTID comparisons safe.
	if _, err := b.c.Execute("SET @slave_gtid_strict_mode=1"); err != nil {
		return errors.Errorf("failed to set @slave_gtid_strict_mode=1: %v", err)
	}

	// Since we use @slave_connect_state, the file and position here are ignored.
	return b.writeBinlogDumpCommand(mysql.Position{Name: "", Pos: 0})
}

// localHostname returns the hostname that register replica would register as.
// this gets truncated to 255 bytes.
func (b *BinlogSyncer) localHostname() string {
	h := b.cfg.Localhost
	if len(h) == 0 {
		h, _ = os.Hostname()
	}
	if len(h) <= 255 {
		return h
	}
	return h[:255]
}

func (b *BinlogSyncer) writeRegisterSlaveCommand() error {
	b.c.ResetSequence()

	hostname := b.localHostname()

	// This should be the name of slave host not the host we are connecting to.
	data := make([]byte, 4+1+4+1+len(hostname)+1+len(b.cfg.User)+1+2+4+4)
	pos := 4

	data[pos] = mysql.COM_REGISTER_SLAVE
	pos++

	binary.LittleEndian.PutUint32(data[pos:], b.cfg.ServerID)
	pos += 4

	// This should be the name of slave hostname not the host we are connecting to.
	data[pos] = uint8(len(hostname))
	pos++
	n := copy(data[pos:], hostname)
	pos += n

	data[pos] = uint8(len(b.cfg.User))
	pos++
	n = copy(data[pos:], b.cfg.User)
	pos += n

	data[pos] = uint8(0)
	pos++

	binary.LittleEndian.PutUint16(data[pos:], b.cfg.Port)
	pos += 2

	// replication rank, not used
	binary.LittleEndian.PutUint32(data[pos:], 0)
	pos += 4

	// master ID, 0 is OK
	binary.LittleEndian.PutUint32(data[pos:], 0)

	return b.c.WritePacket(data)
}

func (b *BinlogSyncer) replySemiSyncACK(p mysql.Position) error {
	b.c.ResetSequence()

	data := make([]byte, 4+1+8+len(p.Name))
	pos := 4
	// semi sync indicator
	data[pos] = SemiSyncIndicator
	pos++

	binary.LittleEndian.PutUint64(data[pos:], uint64(p.Pos))
	pos += 8

	copy(data[pos:], p.Name)

	err := b.c.WritePacket(data)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// retrySync 用于在同步失败后重试同步
func (b *BinlogSyncer) retrySync() error {
	// 加锁保证线程安全
	b.m.Lock()
	// 确保函数退出时解锁
	defer b.m.Unlock()

	// 重置解析器状态
	b.parser.Reset()
	// 清空前一个MySQL GTID事件
	b.prevMySQLGTIDEvent = nil

	// 如果存在前一个GTID集合
	if b.prevGset != nil {
		// 准备日志记录额外信息
		extra := []interface{}{slog.String("GTID Set", b.prevGset.String())}
		// 如果当前GTID集合存在，也加入日志信息
		if b.currGset != nil {
			extra = append(extra, slog.String("last read GTID", b.currGset.String()))
		}
		// 记录开始重新同步的日志
		b.cfg.Logger.Info("begin to re-sync", extra...)

		// 使用GTID集合准备同步
		if err := b.prepareSyncGTID(b.prevGset); err != nil {
			return errors.Trace(err)
		}
	} else {
		// 如果没有GTID集合，使用binlog位置进行同步
		b.cfg.Logger.Info("begin to re-sync",
			slog.String("file", b.nextPos.Name),
			slog.Uint64("position", uint64(b.nextPos.Pos)))
		// 使用binlog位置准备同步
		if err := b.prepareSyncPos(b.nextPos); err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func (b *BinlogSyncer) prepareSyncPos(pos mysql.Position) error {
	// always start from position 4
	if pos.Pos < 4 {
		pos.Pos = 4
	}

	if err := b.prepare(); err != nil {
		return errors.Trace(err)
	}

	if err := b.writeBinlogDumpCommand(pos); err != nil {
		return errors.Trace(err)
	}

	return nil
}

func (b *BinlogSyncer) prepareSyncGTID(gset mysql.GTIDSet) error {
	var err error

	// re establishing network connection here and will start getting binlog events from "gset + 1", thus until first
	// MariadbGTIDEvent/GTIDEvent event is received - we effectively do not have a "current GTID"
	b.currGset = nil

	if err = b.prepare(); err != nil {
		return errors.Trace(err)
	}

	switch b.cfg.Flavor {
	case mysql.MariaDBFlavor:
		err = b.writeBinlogDumpMariadbGTIDCommand(gset)
	default:
		// default use MySQL
		err = b.writeBinlogDumpMysqlGTIDCommand(gset)
	}

	if err != nil {
		return err
	}
	return nil
}

func (b *BinlogSyncer) onStream(s *BinlogStreamer) {
	// 使用defer确保在函数退出时执行清理操作
	defer func() {
		// 捕获panic，防止程序崩溃
		if e := recover(); e != nil {
			// 关闭streamer并传递错误信息和堆栈信息
			s.closeWithError(fmt.Errorf("Err: %v\n Stack: %s", e, mysql.Pstack()))
		}
		// 减少等待组计数器
		b.wg.Done()
	}()

	// 主循环，持续读取binlog事件
	for {
		// 从MySQL服务器读取数据包
		data, err := b.c.ReadPacket()
		// 检查context是否被取消
		select {
		case <-b.ctx.Done():
			// 如果context被取消，关闭streamer并返回
			s.close()
			return
		default:
		}

		// 处理读取数据包时的错误
		if err != nil {
			// 记录错误日志
			b.cfg.Logger.Error(err.Error())
			// we meet connection error, should re-connect again with
			// last nextPos or nextGTID we got.
			// 如果无法获取正确的位置信息，关闭streamer
			if len(b.nextPos.Name) == 0 && b.prevGset == nil {
				// we can't get the correct position, close.
				s.closeWithError(err)
				return
			}

			// 如果禁用了重试同步，直接关闭streamer
			if b.cfg.DisableRetrySync {
				b.cfg.Logger.Warn("retry sync is disabled")
				s.closeWithError(err)
				return
			}

			// 重试同步逻辑
			for {
				select {
				case <-b.ctx.Done():
					s.close()
					return
				case <-time.After(time.Second):
					// 增加重试计数器
					b.retryCount++
					// 尝试重新同步
					if err = b.retrySync(); err != nil {
						// 如果达到最大重试次数，关闭streamer
						if b.cfg.MaxReconnectAttempts > 0 && b.retryCount >= b.cfg.MaxReconnectAttempts {
							b.cfg.Logger.Error(
								"retry sync err, exceeded max retries",
								slog.Any("error", err), slog.Int("maxAttempts", b.cfg.MaxReconnectAttempts),
							)
							s.closeWithError(err)
							return
						}

						// 记录错误并继续重试
						b.cfg.Logger.Error(
							"retry sync err, wait 1s and retry again",
							slog.Any("error", err), slog.Int("retryCount", b.retryCount), slog.Int("maxAttempts", b.cfg.MaxReconnectAttempts),
						)
						continue
					}
				}

				break
			}

			// we connect the server and begin to re-sync again.
			// 重新连接服务器并开始同步
			continue
		}

		// set read timeout
		// 设置读取超时时间
		if b.cfg.ReadTimeout > 0 {
			_ = b.c.SetReadDeadline(utils.Now().Add(b.cfg.ReadTimeout))
		}

		// Reset retry count on successful packet receieve
		// 成功接收数据包后重置重试计数器
		b.retryCount = 0

		// 根据数据包头部进行不同处理
		switch data[0] {
		case mysql.OK_HEADER:
			// Parse the event
			// 解析事件
			e, needACK, err := b.parseEvent(data)
			if err != nil {
				s.closeWithError(err)
				return
			}

			// Handle the event and send ACK if necessary
			// 处理事件并在需要时发送ACK
			err = b.handleEventAndACK(s, e, needACK)
			if err != nil {
				s.closeWithError(err)
				return
			}
		case mysql.ERR_HEADER:
			// 处理错误数据包
			err = b.c.HandleErrorPacket(data)
			s.closeWithError(err)
			return
		case mysql.EOF_HEADER:
			// refer to https://dev.mysql.com/doc/internals/en/com-binlog-dump.html#binlog-dump-non-block
			// when COM_BINLOG_DUMP command use BINLOG_DUMP_NON_BLOCK flag,
			// if there is no more event to send an EOF_Packet instead of blocking the connection
			// 接收EOF数据包，表示当前没有更多binlog事件
			b.cfg.Logger.Info("receive EOF packet, no more binlog event now.")
			continue
		default:
			// 处理无效的流头部
			b.cfg.Logger.Error("invalid stream header", slog.Int("header", int(data[0])))
			continue
		}
	}
}

// parseEvent parses the raw data into a BinlogEvent.
// It only handles parsing and does not perform any side effects.
// Returns the parsed BinlogEvent, a boolean indicating if an ACK is needed, and an error if the
// parsing fails
// parseEvent 将原始数据解析为BinlogEvent
// 它只处理解析，不执行任何副作用
// 返回解析后的BinlogEvent，一个表示是否需要ACK的布尔值，以及解析失败时的错误
func (b *BinlogSyncer) parseEvent(data []byte) (event *BinlogEvent, needACK bool, err error) {
	// Skip OK byte (0x00)
	// 跳过OK字节(0x00)
	data = data[1:]

	// 初始化needACK为false
	needACK = false
	// 检查是否启用了半同步复制并且数据包含半同步指示器
	if b.cfg.SemiSyncEnabled && data[0] == SemiSyncIndicator {
		// 检查是否需要ACK（0x01表示需要）
		needACK = data[1] == 0x01
		// Skip semi-sync header
		// 跳过半同步头部
		data = data[2:]
	}

	// Parse the event using the BinlogParser
	// 使用BinlogParser解析事件
	event, err = b.parser.Parse(data)
	// 如果解析出错，返回错误
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	// 返回解析后的事件、ACK标志和nil错误
	return event, needACK, nil
}

// handleEventAndACK processes an event and sends an ACK if necessary.
// handleEventAndACK 处理事件并在需要时发送ACK
func (b *BinlogSyncer) handleEventAndACK(s *BinlogStreamer, e *BinlogEvent, needACK bool) error {
	// Update the next position based on the event's LogPos
	// 根据事件的LogPos更新下一个位置
	if e.Header.LogPos > 0 {
		// Some events like FormatDescriptionEvent return 0, ignore.
		// 某些事件（如FormatDescriptionEvent）返回0，忽略这些情况
		b.nextPos.Pos = e.Header.LogPos
	}

	// Handle event types to update positions and GTID sets
	// 处理不同类型的事件以更新位置和GTID集合
	switch event := e.Event.(type) {
	case *RotateEvent:
		// 处理binlog文件切换事件
		b.nextPos.Name = string(event.NextLogName)
		b.nextPos.Pos = uint32(event.Position)
		b.cfg.Logger.Info("rotate to next binlog", slog.String("file", b.nextPos.Name), slog.Uint64("position", uint64(b.nextPos.Pos)))

	case *GTIDEvent:
		// 处理GTID事件
		if b.prevGset == nil {
			break
		}
		if b.currGset == nil {
			b.currGset = b.prevGset.Clone()
		}
		// 从字节数组解析UUID
		u, err := uuid.FromBytes(event.SID)
		if err != nil {
			return errors.Trace(err)
		}
		// 将GTID添加到当前GTID集合
		b.currGset.(*mysql.MysqlGTIDSet).AddGTID(u, event.GNO)
		if b.prevMySQLGTIDEvent != nil {
			u, err = uuid.FromBytes(b.prevMySQLGTIDEvent.SID)
			if err != nil {
				return errors.Trace(err)
			}
			b.prevGset.(*mysql.MysqlGTIDSet).AddGTID(u, b.prevMySQLGTIDEvent.GNO)
		}
		b.prevMySQLGTIDEvent = event

	case *MariadbGTIDEvent:
		// 处理MariaDB的GTID事件
		if b.prevGset == nil {
			break
		}
		if b.currGset == nil {
			b.currGset = b.prevGset.Clone()
		}
		prev := b.currGset.Clone()
		err := b.currGset.(*mysql.MariadbGTIDSet).AddSet(&event.GTID)
		if err != nil {
			return errors.Trace(err)
		}
		// Right after reconnect we may see the same GTID as before; update prevGset if currGset changed
		// 重连后可能会看到相同的GTID；如果currGset发生变化则更新prevGset
		if !b.currGset.Equal(prev) {
			b.prevGset = prev
		}

	case *XIDEvent:
		// 处理XID事务提交事件
		if !b.cfg.DiscardGTIDSet {
			event.GSet = b.getCurrentGtidSet()
		}

	case *QueryEvent:
		// 处理SQL查询事件
		if !b.cfg.DiscardGTIDSet {
			event.GSet = b.getCurrentGtidSet()
		}
	}

	// Use SynchronousEventHandler if it's set
	// 如果设置了同步事件处理器则使用它
	if b.cfg.SynchronousEventHandler != nil {
		err := b.cfg.SynchronousEventHandler.HandleEvent(e)
		if err != nil {
			return errors.Trace(err)
		}
	} else {
		// Asynchronous mode: send the event to the streamer channel
		// 异步模式：将事件发送到streamer的channel
		select {
		case s.ch <- e:
		case <-b.ctx.Done():
			return errors.New("sync is being closed...")
		}
	}

	// 如果需要ACK则发送半同步ACK
	if needACK {
		err := b.replySemiSyncACK(b.nextPos)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// getCurrentGtidSet returns a clone of the current GTID set.
func (b *BinlogSyncer) getCurrentGtidSet() mysql.GTIDSet {
	if b.currGset != nil {
		return b.currGset.Clone()
	}
	return nil
}

// LastConnectionID returns last connectionID.
func (b *BinlogSyncer) LastConnectionID() uint32 {
	return b.lastConnectionID
}

// newConnection 创建一个新的MySQL连接
func (b *BinlogSyncer) newConnection(ctx context.Context) (*client.Conn, error) {
	var addr string
	// 如果有指定端口，则组合主机和端口
	if b.cfg.Port != 0 {
		addr = net.JoinHostPort(b.cfg.Host, strconv.Itoa(int(b.cfg.Port)))
	} else {
		// 否则直接使用主机地址
		addr = b.cfg.Host
	}

	// 设置10秒超时的上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel() // 确保取消函数被调用

	// 使用自定义拨号器连接MySQL
	return client.ConnectWithDialer(timeoutCtx, "", addr, b.cfg.User, b.cfg.Password,
		"", b.cfg.Dialer, func(c *client.Conn) error {
			// 设置TLS配置
			c.SetTLSConfig(b.cfg.TLSConfig)
			// 设置客户端属性
			c.SetAttributes(map[string]string{"_client_role": "binary_log_listener"})
			// 设置读超时
			if b.cfg.ReadTimeout > 0 {
				c.ReadTimeout = b.cfg.ReadTimeout
			}
			return nil
		})
}

func (b *BinlogSyncer) killConnection(conn *client.Conn, id uint32) {
	cmd := fmt.Sprintf("KILL %d", id)
	if _, err := conn.Execute(cmd); err != nil {
		b.cfg.Logger.Error("kill connection", slog.Any("error", err), slog.Int64("id", int64(id)))
		// Unknown thread id
		if code := mysql.ErrorCode(err.Error()); code != mysql.ER_NO_SUCH_THREAD {
			b.cfg.Logger.Error(errors.Trace(err).Error())
		}
	}
	b.cfg.Logger.Info("kill last connection", slog.Int64("id", int64(id)))
}
