package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-mysql-org/go-mysql/canal"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/errors"
)

// 定义命令行参数
var (
	host     = flag.String("host", "127.0.0.1", "MySQL host") // MySQL主机地址
	port     = flag.Int("port", 3306, "MySQL port")          // MySQL端口号
	user     = flag.String("user", "root", "MySQL user, must have replication privilege") // MySQL用户名，需具备复制权限
	password = flag.String("password", "", "MySQL password")  // MySQL密码

	flavor = flag.String("flavor", "mysql", "Flavor: mysql or mariadb") // 数据库类型：mysql或mariadb

	serverID  = flag.Int("server-id", 101, "Unique Server ID") // 唯一的服务器ID
	mysqldump = flag.String("mysqldump", "mysqldump", "mysqldump execution path") // mysqldump可执行文件路径

	dbs          = flag.String("dbs", "test", "dump databases, separated by comma") // 要导出的数据库，多个用逗号分隔
	tables       = flag.String("tables", "", "dump tables, separated by comma, will overwrite dbs") // 要导出的表，多个用逗号分隔，会覆盖dbs参数
	tableDB      = flag.String("table_db", "test", "database for dump tables") // 导出表时指定的数据库
	ignoreTables = flag.String("ignore_tables", "", "ignore tables, must be database.table format, separated by comma") // 忽略的表，格式为database.table，多个用逗号分隔

	startName = flag.String("bin_name", "", "start sync from binlog name") // 从指定的binlog文件名开始同步
	startPos  = flag.Uint("bin_pos", 0, "start sync from binlog position of") // 从指定的binlog位置开始同步

	heartbeatPeriod = flag.Duration("heartbeat", 60*time.Second, "master heartbeat period") // 主服务器心跳周期
	readTimeout     = flag.Duration("read_timeout", 90*time.Second, "connection read timeout") // 连接读取超时时间
)

func main() {
	flag.Parse() // 解析命令行参数

	// 验证数据库类型
	err := mysql.ValidateFlavor(*flavor)
	if err != nil {
		fmt.Printf("Flavor error: %v\n", errors.ErrorStack(err))
		return
	}

	// 创建默认的Canal配置
	cfg := canal.NewDefaultConfig()
	cfg.Addr = net.JoinHostPort(*host, strconv.Itoa(*port)) // 设置MySQL地址
	cfg.User = *user                                        // 设置用户名
	cfg.Password = *password                                // 设置密码
	cfg.Flavor = *flavor                                    // 设置数据库类型
	cfg.UseDecimal = true                                   // 启用Decimal类型支持

	cfg.ReadTimeout = *readTimeout         // 设置读取超时时间
	cfg.HeartbeatPeriod = *heartbeatPeriod // 设置心跳周期
	cfg.ServerID = uint32(*serverID)       // 设置服务器ID
	cfg.Dump.ExecutionPath = *mysqldump    // 设置mysqldump路径
	cfg.Dump.DiscardErr = false            // 设置是否忽略错误

	// 创建Canal实例
	c, err := canal.NewCanal(cfg)
	if err != nil {
		fmt.Printf("create canal err %v", err)
		os.Exit(1)
	}

	// 处理忽略的表
	if len(*ignoreTables) > 0 {
		subs := strings.Split(*ignoreTables, ",")
		for _, sub := range subs {
			if seps := strings.Split(sub, "."); len(seps) == 2 {
				c.AddDumpIgnoreTables(seps[0], seps[1]) // 添加忽略的表
			}
		}
	}

	// 处理要导出的表或数据库
	if len(*tables) > 0 && len(*tableDB) > 0 {
		subs := strings.Split(*tables, ",")
		c.AddDumpTables(*tableDB, subs...) // 添加要导出的表
	} else if len(*dbs) > 0 {
		subs := strings.Split(*dbs, ",")
		c.AddDumpDatabases(subs...) // 添加要导出的数据库
	}

	// 设置事件处理器
	c.SetEventHandler(&handler{})

	// 设置binlog同步的起始位置
	startPos := mysql.Position{
		Name: *startName,
		Pos:  uint32(*startPos),
	}

	// 启动Canal
	go func() {
		err = c.RunFrom(startPos)
		if err != nil {
			fmt.Printf("start canal err %v", err)
		}
	}()

	// 监听系统信号，用于优雅退出
	sc := make(chan os.Signal, 1)
	signal.Notify(sc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	<-sc

	// 关闭Canal
	c.Close()
}

// 自定义事件处理器
type handler struct {
	canal.DummyEventHandler
}

// 处理行数据事件
func (h *handler) OnRow(e *canal.RowsEvent) error {
	fmt.Printf("%v\n", e)
	return nil
}

// 返回处理器名称
func (h *handler) String() string {
	return "TestHandler"
}
