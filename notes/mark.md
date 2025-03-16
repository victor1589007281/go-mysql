# 代码解读
## 1. canal
### 1.1 原理
1. 利用Golang官方的dial方法，连接MySQL
2. 向主库注册slave。设置了客户端属性 _client_role: binary_log_listener。MySQL服务器可以通过performance_schema.session_connect_attrs表查看这些属性
3. 根据配置设定或者主库是否开启半同步复制，设置半同步开启参数
4. 发送COM_BINLOG_DUMP_GTID/COM_BINLOG_DUMP command packet给主库，指定开始的binlog位置或者已经获得的GTID集合
5. 持续监听订阅来自主库的binlog event，并解析成对应的数据,持续输出到管道。订阅过程中，需要根据前面的半同步开启状态决定是否发送ACK给主库
6. 消费管道的数据