package canal

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
	"github.com/go-mysql-org/go-mysql/schema"
	"github.com/go-mysql-org/go-mysql/utils"
	"github.com/pingcap/errors"
	"github.com/pingcap/tidb/pkg/parser/ast"
)

// startSyncer 启动binlog同步器
func (c *Canal) startSyncer() (*replication.BinlogStreamer, error) {
	// 获取主库的GTID集合
	gset := c.master.GTIDSet()
	// 如果GTID集合为空或为空字符串
	if gset == nil || gset.String() == "" {
		// 获取当前binlog位置
		pos := c.master.Position()
		// 从指定位置开始同步
		s, err := c.syncer.StartSync(pos)
		if err != nil {
			// 返回错误信息
			return nil, errors.Errorf("start sync replication at binlog %v error %v", pos, err)
		}
		// 记录开始同步的日志信息
		c.cfg.Logger.Info("start sync binlog at binlog file", slog.Any("pos", pos))
		// 返回binlog流
		return s, nil
	} else {
		// 克隆GTID集合
		gsetClone := gset.Clone()
		// 从指定GTID集合开始同步
		s, err := c.syncer.StartSyncGTID(gset)
		if err != nil {
			// 返回错误信息
			return nil, errors.Errorf("start sync replication at GTID set %v error %v", gset, err)
		}
		// 记录开始同步的日志信息
		c.cfg.Logger.Info("start sync binlog at GTID set", slog.Any("gset", gsetClone))
		// 返回binlog流
		return s, nil
	}
}

// runSyncBinlog 运行binlog同步
func (c *Canal) runSyncBinlog() error {
	// 启动同步器
	s, err := c.startSyncer()
	if err != nil {
		// 如果启动失败返回错误
		return err
	}

	// 持续循环处理binlog事件
	for {
		// 获取下一个binlog事件
		ev, err := s.GetEvent(c.ctx)
		if err != nil {
			// 如果获取事件失败返回错误
			return errors.Trace(err)
		}

		// Update the delay between the Canal and the Master before the handler hooks are called
		// 在调用处理程序钩子之前更新Canal和Master之间的延迟
		c.updateReplicationDelay(ev)

		// 根据事件类型进行处理
		switch e := ev.Event.(type) {
		case *replication.RotateEvent:
			// If the timestamp equals zero, the received rotate event is a fake rotate event
			// and contains only the name of the next binlog file. Its log position should be
			// ignored.
			// See https://github.com/mysql/mysql-server/blob/8e797a5d6eb3a87f16498edcb7261a75897babae/sql/rpl_binlog_sender.h#L235
			// and https://github.com/mysql/mysql-server/blob/8cc757da3d87bf4a1f07dcfb2d3c96fed3806870/sql/rpl_binlog_sender.cc#L899
			// 如果时间戳为0，表示这是一个假的rotate事件
			if ev.Header.Timestamp == 0 {
				// 获取下一个binlog文件名
				fakeRotateLogName := string(e.NextLogName)
				// 记录收到假rotate事件的日志
				c.cfg.Logger.Info("received fake rotate event", slog.String("nextLogName", string(e.NextLogName)))

				// 如果日志名发生变化
				if fakeRotateLogName != c.master.Position().Name {
					// 记录日志名变化的日志
					c.cfg.Logger.Info("log name changed, the fake rotate event will be handled as a real rotate event")
				} else {
					// 否则继续下一个事件
					continue
				}
			}
		}

		// 处理当前事件
		err = c.handleEvent(ev)
		if err != nil {
			// 如果处理失败返回错误
			return err
		}
	}
}

// handleEvent 处理binlog事件
func (c *Canal) handleEvent(ev *replication.BinlogEvent) error {
	// 是否需要保存位置
	savePos := false
	// 是否强制保存
	force := false
	// 获取当前主库位置
	pos := c.master.Position()
	var err error

	// 记录当前事件位置
	curPos := pos.Pos

	// next binlog pos
	// 更新位置到当前事件结束位置
	pos.Pos = ev.Header.LogPos

	// We only save position with RotateEvent and XIDEvent.
	// For RowsEvent, we can't save the position until meeting XIDEvent
	// which tells the whole transaction is over.
	// TODO: If we meet any DDL query, we must save too.
	// 根据不同类型的事件进行处理
	switch e := ev.Event.(type) {
	case *replication.RotateEvent:
		// 更新binlog文件名和位置
		pos.Name = string(e.NextLogName)
		pos.Pos = uint32(e.Position)
		// 记录日志
		c.cfg.Logger.Info("rotate binlog", slog.Any("pos", pos))
		// 需要保存位置
		savePos = true
		force = true
		// 调用事件处理器的OnRotate方法
		if err = c.eventHandler.OnRotate(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.RowsEvent:
		// we only focus row based event
		// 处理行变更事件
		if err := c.handleRowsEvent(ev); err != nil {
			c.cfg.Logger.Error("handle rows event", slog.String("file", pos.Name), slog.Uint64("position", uint64(curPos)), slog.Any("error", err))
			return errors.Trace(err)
		}
		return nil
	case *replication.TransactionPayloadEvent:
		// handle subevent row by row
		// 处理事务负载事件中的每个子事件
		ev := ev.Event.(*replication.TransactionPayloadEvent)
		for _, subEvent := range ev.Events {
			err = c.handleEvent(subEvent)
			if err != nil {
				c.cfg.Logger.Error("handle transaction payload subevent", slog.String("file", pos.Name), slog.Uint64("position", uint64(curPos)), slog.Any("error", err))
				return errors.Trace(err)
			}
		}
		return nil
	case *replication.XIDEvent:
		// 需要保存位置
		savePos = true
		// try to save the position later
		// 调用事件处理器的OnXID方法
		if err := c.eventHandler.OnXID(ev.Header, pos); err != nil {
			return errors.Trace(err)
		}
		// 更新GTID集合
		if e.GSet != nil {
			c.master.UpdateGTIDSet(e.GSet)
		}
	case *replication.MariadbGTIDEvent:
		// 处理MariaDB GTID事件
		if err := c.eventHandler.OnGTID(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.GTIDEvent:
		// 处理MySQL GTID事件
		if err := c.eventHandler.OnGTID(ev.Header, e); err != nil {
			return errors.Trace(err)
		}
	case *replication.RowsQueryEvent:
		// 处理RowsQuery事件
		if err := c.eventHandler.OnRowsQueryEvent(e); err != nil {
			return errors.Trace(err)
		}
	case *replication.QueryEvent:
		// 解析SQL语句
		stmts, _, err := c.parser.Parse(string(e.Query), "", "")
		if err != nil {
			// The parser does not understand all syntax.
			// For example, it won't parse [CREATE|DROP] TRIGGER statements.
			// 记录解析错误日志
			c.cfg.Logger.Error("error parsing query, will skip this event", slog.String("query", string(e.Query)), slog.Any("error", err))
			return nil
		}
		// 如果有解析出的语句，需要保存位置
		if len(stmts) > 0 {
			savePos = true
		}
		// 处理每个解析出的语句
		for _, stmt := range stmts {
			nodes := parseStmt(stmt)
			for _, node := range nodes {
				if node.db == "" {
					node.db = string(e.Schema)
				}
				// 更新表结构信息
				if err = c.updateTable(ev.Header, node.db, node.table); err != nil {
					return errors.Trace(err)
				}
			}
			if len(nodes) > 0 {
				force = true
				// Now we only handle Table Changed DDL, maybe we will support more later.
				// 调用事件处理器的OnDDL方法
				if err = c.eventHandler.OnDDL(ev.Header, pos, e); err != nil {
					return errors.Trace(err)
				}
			}
		}
		// 如果有GTID集合，更新GTID
		if savePos && e.GSet != nil {
			c.master.UpdateGTIDSet(e.GSet)
		}
	default:
		return nil
	}

	// 如果需要保存位置
	if savePos {
		// 更新主库位置
		c.master.Update(pos)
		// 更新时间戳
		c.master.UpdateTimestamp(ev.Header.Timestamp)

		// 调用事件处理器的OnPosSynced方法
		if err := c.eventHandler.OnPosSynced(ev.Header, pos, c.master.GTIDSet(), force); err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

type node struct {
	db    string
	table string
}

func parseStmt(stmt ast.StmtNode) (ns []*node) {
	switch t := stmt.(type) {
	case *ast.RenameTableStmt:
		ns = make([]*node, len(t.TableToTables))
		for i, tableInfo := range t.TableToTables {
			ns[i] = &node{
				db:    tableInfo.OldTable.Schema.String(),
				table: tableInfo.OldTable.Name.String(),
			}
		}
	case *ast.AlterTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.DropTableStmt:
		ns = make([]*node, len(t.Tables))
		for i, table := range t.Tables {
			ns[i] = &node{
				db:    table.Schema.String(),
				table: table.Name.String(),
			}
		}
	case *ast.CreateTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.TruncateTableStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.CreateIndexStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	case *ast.DropIndexStmt:
		n := &node{
			db:    t.Table.Schema.String(),
			table: t.Table.Name.String(),
		}
		ns = []*node{n}
	}
	return ns
}

func (c *Canal) updateTable(header *replication.EventHeader, db, table string) (err error) {
	c.ClearTableCache([]byte(db), []byte(table))
	c.cfg.Logger.Info("table structure changed, clear table cache", slog.String("database", db), slog.String("table", table))
	if err = c.eventHandler.OnTableChanged(header, db, table); err != nil && errors.Cause(err) != schema.ErrTableNotExist {
		return errors.Trace(err)
	}
	return
}

func (c *Canal) updateReplicationDelay(ev *replication.BinlogEvent) {
	var newDelay uint32
	now := uint32(utils.Now().Unix())
	if now >= ev.Header.Timestamp {
		newDelay = now - ev.Header.Timestamp
	}
	atomic.StoreUint32(c.delay, newDelay)
}

func (c *Canal) handleRowsEvent(e *replication.BinlogEvent) error {
	ev := e.Event.(*replication.RowsEvent)

	// Caveat: table may be altered at runtime.
	schemaName := string(ev.Table.Schema)
	tableName := string(ev.Table.Table)

	t, err := c.GetTable(schemaName, tableName)
	if err != nil {
		e := errors.Cause(err)
		// ignore errors below
		if e == ErrExcludedTable || e == schema.ErrTableNotExist || e == schema.ErrMissingTableMeta {
			err = nil
		}

		return err
	}
	var action string
	switch e.Header.EventType {
	case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2, replication.MARIADB_WRITE_ROWS_COMPRESSED_EVENT_V1:
		action = InsertAction
	case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2, replication.MARIADB_DELETE_ROWS_COMPRESSED_EVENT_V1:
		action = DeleteAction
	case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2, replication.MARIADB_UPDATE_ROWS_COMPRESSED_EVENT_V1:
		action = UpdateAction
	default:
		return errors.Errorf("%s not supported now", e.Header.EventType)
	}
	events := newRowsEvent(t, action, ev.Rows, e.Header)
	return c.eventHandler.OnRow(events)
}

func (c *Canal) FlushBinlog() error {
	_, err := c.Execute("FLUSH BINARY LOGS")
	return errors.Trace(err)
}

func (c *Canal) WaitUntilPos(pos mysql.Position, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	for {
		select {
		case <-timer.C:
			return errors.Errorf("wait position %v too long > %s", pos, timeout)
		default:
			if !c.cfg.DisableFlushBinlogWhileWaiting {
				err := c.FlushBinlog()
				if err != nil {
					return errors.Trace(err)
				}
			}
			curPos := c.master.Position()
			if curPos.Compare(pos) >= 0 {
				return nil
			} else {
				c.cfg.Logger.Debug("master pos is behind, wait to catch up", slog.String("master file", curPos.Name), slog.Uint64("master position", uint64(curPos.Pos)),
					slog.String("target file", pos.Name), slog.Uint64("target position", uint64(curPos.Pos)))
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (c *Canal) GetMasterPos() (mysql.Position, error) {
	showBinlogStatus := "SHOW BINARY LOG STATUS"
	if eq, err := c.conn.CompareServerVersion("8.4.0"); (err == nil) && (eq < 0) {
		showBinlogStatus = "SHOW MASTER STATUS"
	}

	rr, err := c.Execute(showBinlogStatus)
	if err != nil {
		return mysql.Position{}, errors.Trace(err)
	}

	name, _ := rr.GetString(0, 0)
	pos, _ := rr.GetInt(0, 1)

	return mysql.Position{Name: name, Pos: uint32(pos)}, nil
}

func (c *Canal) GetMasterGTIDSet() (mysql.GTIDSet, error) {
	query := ""
	switch c.cfg.Flavor {
	case mysql.MariaDBFlavor:
		query = "SELECT @@GLOBAL.gtid_current_pos"
	default:
		query = "SELECT @@GLOBAL.GTID_EXECUTED"
	}
	rr, err := c.Execute(query)
	if err != nil {
		return nil, errors.Trace(err)
	}
	gx, err := rr.GetString(0, 0)
	if err != nil {
		return nil, errors.Trace(err)
	}
	gset, err := mysql.ParseGTIDSet(c.cfg.Flavor, gx)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return gset, nil
}

func (c *Canal) CatchMasterPos(timeout time.Duration) error {
	pos, err := c.GetMasterPos()
	if err != nil {
		return errors.Trace(err)
	}

	return c.WaitUntilPos(pos, timeout)
}
