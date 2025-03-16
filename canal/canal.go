package canal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/dump"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser"
)

// Canal can sync your MySQL data into everywhere, like Elasticsearch, Redis, etc...
// MySQL must open row format for binlog
// Canal 可以将 MySQL 数据同步到任何地方，如 Elasticsearch、Redis 等
// MySQL 必须开启 binlog 的行格式
type Canal struct {
	m sync.Mutex // 互斥锁，用于保护共享资源

	cfg *Config // Canal 配置

	parser     *parser.Parser            // SQL 解析器
	master     *masterInfo               // 主库信息
	dumper     *dump.Dumper              // mysqldump 工具
	dumped     bool                      // 是否已经执行过 dump
	dumpDoneCh chan struct{}             // dump 完成的通知通道
	syncer     *replication.BinlogSyncer // binlog 同步器

	eventHandler EventHandler // 事件处理器

	connLock sync.Mutex   // 连接锁
	conn     *client.Conn // MySQL 连接

	tableLock          sync.RWMutex             // 表锁
	tables             map[string]*schema.Table // 表元数据缓存
	errorTablesGetTime map[string]time.Time     // 获取表元数据失败的时间记录

	tableMatchCache   map[string]bool  // 表匹配缓存
	includeTableRegex []*regexp.Regexp // 包含表的正则表达式
	excludeTableRegex []*regexp.Regexp // 排除表的正则表达式

	delay *uint32 // 同步延迟

	ctx    context.Context    // 上下文
	cancel context.CancelFunc // 取消函数
}

// canal will retry fetching unknown table's meta after UnknownTableRetryPeriod
// canal 会在 UnknownTableRetryPeriod 后重试获取未知表的元数据
var (
	UnknownTableRetryPeriod = time.Second * time.Duration(10)   // 重试获取表元数据的周期
	ErrExcludedTable        = errors.New("excluded table meta") // 表被排除的错误
)

// NewCanal 创建一个新的 Canal 实例
func NewCanal(cfg *Config) (*Canal, error) {
	c := new(Canal)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default() // 使用默认的日志记录器
	}
	if cfg.Dialer == nil {
		dialer := &net.Dialer{}
		cfg.Dialer = dialer.DialContext // 使用默认的拨号器
	}
	c.cfg = cfg

	c.ctx, c.cancel = context.WithCancel(context.Background()) // 创建上下文和取消函数

	c.dumpDoneCh = make(chan struct{})        // 初始化 dump 完成通道
	c.eventHandler = &DummyEventHandler{}     // 使用默认的事件处理器
	c.parser = parser.New()                   // 初始化 SQL 解析器
	c.tables = make(map[string]*schema.Table) // 初始化表元数据缓存
	if c.cfg.DiscardNoMetaRowEvent {
		c.errorTablesGetTime = make(map[string]time.Time) // 初始化获取表元数据失败的时间记录
	}
	c.master = &masterInfo{logger: c.cfg.Logger} // 初始化主库信息

	c.delay = new(uint32) // 初始化同步延迟

	var err error

	if err = c.prepareDumper(); err != nil { // 准备 mysqldump 工具
		return nil, errors.Trace(err)
	}

	if err = c.prepareSyncer(); err != nil { // 准备 binlog 同步器
		return nil, errors.Trace(err)
	}

	if err := c.checkBinlogRowFormat(); err != nil { // 检查 binlog 格式
		return nil, errors.Trace(err)
	}

	if err := c.initTableFilter(); err != nil { // 初始化表过滤器
		return nil, errors.Trace(err)
	}

	return c, nil
}

// initTableFilter 初始化表过滤器
func (c *Canal) initTableFilter() error {
	if n := len(c.cfg.IncludeTableRegex); n > 0 { // 如果有包含表的正则表达式
		c.includeTableRegex = make([]*regexp.Regexp, n)
		for i, val := range c.cfg.IncludeTableRegex {
			reg, err := regexp.Compile(val) // 编译正则表达式
			if err != nil {
				return errors.Trace(err)
			}
			c.includeTableRegex[i] = reg
		}
	}

	if n := len(c.cfg.ExcludeTableRegex); n > 0 { // 如果有排除表的正则表达式
		c.excludeTableRegex = make([]*regexp.Regexp, n)
		for i, val := range c.cfg.ExcludeTableRegex {
			reg, err := regexp.Compile(val) // 编译正则表达式
			if err != nil {
				return errors.Trace(err)
			}
			c.excludeTableRegex[i] = reg
		}
	}

	if c.includeTableRegex != nil || c.excludeTableRegex != nil { // 如果有表过滤器
		c.tableMatchCache = make(map[string]bool) // 初始化表匹配缓存
	}
	return nil
}

// prepareDumper 准备 mysqldump 工具
func (c *Canal) prepareDumper() error {
	var err error
	dumpPath := c.cfg.Dump.ExecutionPath // mysqldump 可执行文件路径
	if len(dumpPath) == 0 {
		// ignore mysqldump, use binlog only
		// 忽略 mysqldump，仅使用 binlog
		return nil
	}

	if c.dumper, err = dump.NewDumper(dumpPath,
		c.cfg.Addr, c.cfg.User, c.cfg.Password); err != nil { // 创建 mysqldump 工具
		return errors.Trace(err)
	}

	if c.dumper == nil {
		// no mysqldump, use binlog only
		// 没有 mysqldump，仅使用 binlog
		return nil
	}

	// use the same logger for the dumper
	// 为 dumper 使用相同的日志记录器
	c.dumper.Logger = c.cfg.Logger

	dbs := c.cfg.Dump.Databases   // 要导出的数据库
	tables := c.cfg.Dump.Tables   // 要导出的表
	tableDB := c.cfg.Dump.TableDB // 导出表时指定的数据库

	if len(tables) == 0 {
		c.dumper.AddDatabases(dbs...) // 添加要导出的数据库
	} else {
		c.dumper.AddTables(tableDB, tables...) // 添加要导出的表
	}

	charset := c.cfg.Charset     // 字符集
	c.dumper.SetCharset(charset) // 设置字符集

	c.dumper.SetWhere(c.cfg.Dump.Where)                         // 设置导出条件
	c.dumper.SkipMasterData(c.cfg.Dump.SkipMasterData)          // 是否跳过主库数据
	c.dumper.SetMaxAllowedPacket(c.cfg.Dump.MaxAllowedPacketMB) // 设置最大允许的数据包大小
	c.dumper.SetProtocol(c.cfg.Dump.Protocol)                   // 设置协议
	c.dumper.SetExtraOptions(c.cfg.Dump.ExtraOptions)           // 设置额外的选项
	// Use hex blob for mysqldump
	// 使用十六进制格式导出 blob
	c.dumper.SetHexBlob(true)

	for _, ignoreTable := range c.cfg.Dump.IgnoreTables { // 处理忽略的表
		if seps := strings.Split(ignoreTable, ","); len(seps) == 2 {
			c.dumper.AddIgnoreTables(seps[0], seps[1]) // 添加忽略的表
		}
	}

	if c.cfg.Dump.DiscardErr { // 是否忽略错误
		c.dumper.SetErrOut(io.Discard) // 忽略错误输出
	} else {
		c.dumper.SetErrOut(os.Stderr) // 输出错误到标准错误
	}

	return nil
}

// GetDelay 获取当前的同步延迟
func (c *Canal) GetDelay() uint32 {
	return atomic.LoadUint32(c.delay) // 原子加载延迟值
}

// Run will first try to dump all data from MySQL master `mysqldump`,
// then sync from the binlog position in the dump data.
// It will run forever until meeting an error or Canal closed.
// Run 首先尝试从 MySQL 主库 `mysqldump` 导出所有数据，
// 然后从导出数据中的 binlog 位置开始同步。
// 它将一直运行，直到遇到错误或 Canal 关闭。
func (c *Canal) Run() error {
	return c.run()
}

// RunFrom will sync from the binlog position directly, ignore mysqldump.
// RunFrom 直接从指定的 binlog 位置开始同步，忽略 mysqldump。
func (c *Canal) RunFrom(pos mysql.Position) error {
	c.master.Update(pos) // 更新主库信息

	return c.Run()
}

// StartFromGTID 从指定的 GTID 开始同步
func (c *Canal) StartFromGTID(set mysql.GTIDSet) error {
	c.master.UpdateGTIDSet(set) // 更新主库的 GTID 信息

	return c.Run()
}

// Dump all data from MySQL master `mysqldump`, ignore sync binlog.
// Dump 从 MySQL 主库 `mysqldump` 导出所有数据，忽略 binlog 同步。
func (c *Canal) Dump() error {
	if c.dumped {
		return errors.New("the method Dump can't be called twice") // 不能重复调用 Dump 方法
	}
	c.dumped = true
	defer close(c.dumpDoneCh) // 关闭 dump 完成通道
	return c.dump()
}

// run 执行 Canal 的主要逻辑
func (c *Canal) run() error {
	defer func() {
		c.cancel() // 取消上下文
	}()

	c.master.UpdateTimestamp(uint32(utils.Now().Unix())) // 更新主库时间戳

	if !c.dumped {
		c.dumped = true

		err := c.tryDump()  // 尝试执行 dump
		close(c.dumpDoneCh) // 关闭 dump 完成通道

		if err != nil {
			c.cfg.Logger.Error("canal dump mysql err", slog.Any("error", err)) // 记录 dump 错误
			return errors.Trace(err)
		}
	}

	if err := c.runSyncBinlog(); err != nil { // 执行 binlog 同步
		if errors.Cause(err) != context.Canceled {
			c.cfg.Logger.Error("canal start sync binlog err", slog.Any("error", err)) // 记录 binlog 同步错误
			return errors.Trace(err)
		}
	}

	return nil
}

// Close 关闭 Canal
func (c *Canal) Close() {
	c.cfg.Logger.Info("closing canal") // 记录关闭日志
	c.m.Lock()
	defer c.m.Unlock()

	c.cancel()       // 取消上下文
	c.syncer.Close() // 关闭 binlog 同步器
	c.connLock.Lock()
	if c.conn != nil {
		c.conn.Close() // 关闭 MySQL 连接
		c.conn = nil
	}
	c.connLock.Unlock()

	_ = c.eventHandler.OnPosSynced(nil, c.master.Position(), c.master.GTIDSet(), true) // 触发同步完成事件
}

// WaitDumpDone 等待 dump 完成
func (c *Canal) WaitDumpDone() <-chan struct{} {
	return c.dumpDoneCh
}

// Ctx 返回 Canal 的上下文
func (c *Canal) Ctx() context.Context {
	return c.ctx
}

// checkTableMatch 检查表是否匹配过滤器
func (c *Canal) checkTableMatch(key string) bool {
	// no filter, return true
	// 如果没有过滤器，返回 true
	if c.tableMatchCache == nil {
		return true
	}

	c.tableLock.RLock()
	rst, ok := c.tableMatchCache[key] // 从缓存中获取匹配结果
	c.tableLock.RUnlock()
	if ok {
		// cache hit
		// 缓存命中
		return rst
	}
	matchFlag := false
	// check include
	// 检查包含表的正则表达式
	if c.includeTableRegex != nil {
		for _, reg := range c.includeTableRegex {
			if reg.MatchString(key) {
				matchFlag = true
				break
			}
		}
	} else {
		matchFlag = true
	}

	// check exclude
	// 检查排除表的正则表达式
	if matchFlag && c.excludeTableRegex != nil {
		for _, reg := range c.excludeTableRegex {
			if reg.MatchString(key) {
				matchFlag = false
				break
			}
		}
	}
	c.tableLock.Lock()
	c.tableMatchCache[key] = matchFlag // 更新缓存
	c.tableLock.Unlock()
	return matchFlag
}

// GetTable 获取表的元数据
func (c *Canal) GetTable(db string, table string) (*schema.Table, error) {
	key := fmt.Sprintf("%s.%s", db, table)
	// if table is excluded, return error and skip parsing event or dump
	// 如果表被排除，返回错误并跳过解析事件或 dump
	if !c.checkTableMatch(key) {
		return nil, ErrExcludedTable
	}
	c.tableLock.RLock()
	t, ok := c.tables[key] // 从缓存中获取表元数据
	c.tableLock.RUnlock()

	if ok {
		return t, nil
	}

	if c.cfg.DiscardNoMetaRowEvent {
		c.tableLock.RLock()
		lastTime, ok := c.errorTablesGetTime[key] // 获取上次获取表元数据失败的时间
		c.tableLock.RUnlock()
		if ok && time.Since(lastTime) < UnknownTableRetryPeriod {
			return nil, schema.ErrMissingTableMeta // 如果未超过重试周期，返回表元数据缺失错误
		}
	}

	t, err := schema.NewTable(c, db, table) // 获取表元数据
	if err != nil {
		// check table not exists
		// 检查表是否存在
		if ok, err1 := schema.IsTableExist(c, db, table); err1 == nil && !ok {
			return nil, schema.ErrTableNotExist // 表不存在错误
		}
		// work around : RDS HAHeartBeat
		// ref : https://github.com/alibaba/canal/blob/master/parse/src/main/java/com/alibaba/otter/canal/parse/inbound/mysql/dbsync/LogEventConvert.java#L385
		// issue : https://github.com/alibaba/canal/issues/222
		// This is a common error in RDS that canal can't get HAHealthCheckSchema's meta, so we mock a table meta.
		// If canal just skip and log error, as RDS HA heartbeat interval is very short, so too many HAHeartBeat errors will be logged.
		// 这是一个 RDS 的常见错误，canal 无法获取 HAHealthCheckSchema 的元数据，因此我们模拟一个表元数据。
		// 如果 canal 只是跳过并记录错误，由于 RDS HA 心跳间隔非常短，因此会记录大量 HAHeartBeat 错误。
		if key == schema.HAHealthCheckSchema {
			// mock ha_health_check meta
			// 模拟 ha_health_check 元数据
			ta := &schema.Table{
				Schema:  db,
				Name:    table,
				Columns: make([]schema.TableColumn, 0, 2),
				Indexes: make([]*schema.Index, 0),
			}
			ta.AddColumn("id", "bigint(20)", "", "") // 添加 id 列
			ta.AddColumn("type", "char(1)", "", "")  // 添加 type 列
			c.tableLock.Lock()
			c.tables[key] = ta // 更新缓存
			c.tableLock.Unlock()
			return ta, nil
		}
		// if DiscardNoMetaRowEvent is true, we just log this error
		// 如果 DiscardNoMetaRowEvent 为 true，我们只记录这个错误
		if c.cfg.DiscardNoMetaRowEvent {
			c.tableLock.Lock()
			c.errorTablesGetTime[key] = utils.Now() // 记录获取表元数据失败的时间
			c.tableLock.Unlock()
			// log error and return ErrMissingTableMeta
			// 记录错误并返回表元数据缺失错误
			c.cfg.Logger.Error("canal get table meta err", slog.Any("error", errors.Trace(err)))
			return nil, schema.ErrMissingTableMeta
		}
		return nil, err
	}

	c.tableLock.Lock()
	c.tables[key] = t // 更新缓存
	if c.cfg.DiscardNoMetaRowEvent {
		// if get table info success, delete this key from errorTablesGetTime
		// 如果成功获取表元数据，从 errorTablesGetTime 中删除该键
		delete(c.errorTablesGetTime, key)
	}
	c.tableLock.Unlock()

	return t, nil
}

// ClearTableCache clear table cache
// ClearTableCache 清除表缓存
func (c *Canal) ClearTableCache(db []byte, table []byte) {
	key := fmt.Sprintf("%s.%s", db, table)
	c.tableLock.Lock()
	delete(c.tables, key)
	if c.cfg.DiscardNoMetaRowEvent {
		delete(c.errorTablesGetTime, key)
	}
	c.tableLock.Unlock()
}

// SetTableCache 设置表缓存
// SetTableCache sets table cache value for the given table
func (c *Canal) SetTableCache(db []byte, table []byte, schema *schema.Table) {
	key := fmt.Sprintf("%s.%s", db, table)
	c.tableLock.Lock()
	c.tables[key] = schema
	if c.cfg.DiscardNoMetaRowEvent {
		// if get table info success, delete this key from errorTablesGetTime
		// 如果成功获取表元数据，从 errorTablesGetTime 中删除该键
		delete(c.errorTablesGetTime, key)
	}
	c.tableLock.Unlock()
}

// CheckBinlogRowImage 检查 MySQL binlog 行格式，必须是 FULL、MINIMAL 或 NOBLOB
// CheckBinlogRowImage checks MySQL binlog row image, must be in FULL, MINIMAL, NOBLOB
func (c *Canal) CheckBinlogRowImage(image string) error {
	// need to check MySQL binlog row image? full, minimal or noblob?
	// 需要检查 MySQL binlog 行格式吗？full、minimal 或 noblob？
	// now only log
	// 现在只记录日志
	if c.cfg.Flavor == mysql.MySQLFlavor {
		if res, err := c.Execute(`SHOW GLOBAL VARIABLES LIKE 'binlog_row_image'`); err != nil {
			return errors.Trace(err)
		} else {
			// MySQL has binlog row image from 5.6, so older will return empty
			// MySQL 从 5.6 开始支持 binlog 行格式，旧版本会返回空
			rowImage, _ := res.GetString(0, 1)
			if rowImage != "" && !strings.EqualFold(rowImage, image) {
				return errors.Errorf("MySQL uses %s binlog row image, but we want %s", rowImage, image)
			}
		}
	}

	return nil
}

// checkBinlogRowFormat 检查 binlog 格式是否为 ROW
func (c *Canal) checkBinlogRowFormat() error {
	res, err := c.Execute(`SHOW GLOBAL VARIABLES LIKE 'binlog_format';`)
	if err != nil {
		return errors.Trace(err)
	} else if f, _ := res.GetString(0, 1); f != "ROW" {
		return errors.Errorf("binlog must ROW format, but %s now", f)
	}

	return nil
}

// prepareSyncer 准备 binlog 同步器
func (c *Canal) prepareSyncer() error {
	cfg := replication.BinlogSyncerConfig{
		ServerID:                c.cfg.ServerID,                // 服务器 ID
		Flavor:                  c.cfg.Flavor,                  // 数据库类型
		User:                    c.cfg.User,                    // 用户名
		Password:                c.cfg.Password,                // 密码
		Charset:                 c.cfg.Charset,                 // 字符集
		HeartbeatPeriod:         c.cfg.HeartbeatPeriod,         // 心跳周期
		ReadTimeout:             c.cfg.ReadTimeout,             // 读取超时时间
		UseDecimal:              c.cfg.UseDecimal,              // 是否使用 Decimal 类型
		ParseTime:               c.cfg.ParseTime,               // 是否解析时间
		SemiSyncEnabled:         c.cfg.SemiSyncEnabled,         // 是否启用半同步
		MaxReconnectAttempts:    c.cfg.MaxReconnectAttempts,    // 最大重试次数
		DisableRetrySync:        c.cfg.DisableRetrySync,        // 是否禁用重试同步
		TimestampStringLocation: c.cfg.TimestampStringLocation, // 时间戳字符串位置
		TLSConfig:               c.cfg.TLSConfig,               // TLS 配置
		Logger:                  c.cfg.Logger,                  // 日志记录器
		Dialer:                  c.cfg.Dialer,                  // 拨号器
		Localhost:               c.cfg.Localhost,               // 本地主机
		EventCacheCount:         c.cfg.EventCacheCount,         // 事件缓存数量
		RowsEventDecodeFunc: func(event *replication.RowsEvent, data []byte) error {
			pos, err := event.DecodeHeader(data) // 解码事件头
			if err != nil {
				return err
			}

			key := fmt.Sprintf("%s.%s", string(event.Table.Schema), string(event.Table.Table))
			if !c.checkTableMatch(key) { // 检查表是否匹配
				return nil
			}

			return event.DecodeData(pos, data) // 解码事件数据
		},
	}

	if strings.Contains(c.cfg.Addr, "/") {
		cfg.Host = c.cfg.Addr // 设置主机地址
	} else {
		host, port, err := net.SplitHostPort(c.cfg.Addr) // 分割主机和端口
		if err != nil {
			return errors.Errorf("invalid MySQL address format %s, must host:port", c.cfg.Addr)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16) // 解析端口号
		if err != nil {
			return errors.Trace(err)
		}

		cfg.Host = host               // 设置主机
		cfg.Port = uint16(portNumber) // 设置端口
	}

	c.syncer = replication.NewBinlogSyncer(cfg) // 创建 binlog 同步器

	return nil
}

// connect 连接到 MySQL
func (c *Canal) connect(options ...client.Option) (*client.Conn, error) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Second*10) // 设置超时上下文
	defer cancel()

	return client.ConnectWithDialer(ctx, "", c.cfg.Addr,
		c.cfg.User, c.cfg.Password, "", c.cfg.Dialer, options...) // 使用拨号器连接
}

// Execute 执行 SQL 语句
// Execute a SQL
func (c *Canal) Execute(cmd string, args ...interface{}) (rr *mysql.Result, err error) {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	argF := make([]client.Option, 0)
	if c.cfg.TLSConfig != nil {
		argF = append(argF, func(conn *client.Conn) error {
			conn.SetTLSConfig(c.cfg.TLSConfig) // 设置 TLS 配置
			return nil
		})
	}

	retryNum := 3
	for i := 0; i < retryNum; i++ {
		if c.conn == nil {
			c.conn, err = c.connect(argF...) // 连接 MySQL
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		rr, err = c.conn.Execute(cmd, args...) // 执行 SQL 语句
		if err != nil {
			if mysql.ErrorEqual(err, mysql.ErrBadConn) { // 检查是否为坏连接错误
				c.conn.Close()
				c.conn = nil
				continue
			}
			return nil, err
		}
		break
	}
	return rr, err
}

// SyncedPosition 获取已同步的 binlog 位置
func (c *Canal) SyncedPosition() mysql.Position {
	return c.master.Position()
}

// SyncedTimestamp 获取已同步的时间戳
func (c *Canal) SyncedTimestamp() uint32 {
	return c.master.Timestamp()
}

// SyncedGTIDSet 获取已同步的 GTID 集合
func (c *Canal) SyncedGTIDSet() mysql.GTIDSet {
	return c.master.GTIDSet()
}
