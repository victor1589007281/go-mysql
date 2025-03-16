# 代码解读
## 1. canal
### 1.1 原理
1. 利用Golang官方的dial方法，连接MySQL。然后进行握手。读取服务器初始握手包信息，发送客户端认证握手信息，处理认证结果（这些都是一些特别的二进制格式数据包）。
2. 向主库注册slave。设置了客户端属性 _client_role: binary_log_listener。MySQL服务器可以通过performance_schema.session_connect_attrs表查看这些属性。发送COM_REGISTER_SLAVE command packet给主库，然后读取回包，确认是OK。另外，还会设置master_heartbeat_period参数，用于心跳检测，表明slave的存活状态。
3. 根据配置设定或者主库是否开启半同步复制，设置半同步开启参数
4. 发送COM_BINLOG_DUMP_GTID/COM_BINLOG_DUMP command packet给主库，指定开始的binlog位置或者已经获得的GTID集合
5. 持续监听订阅来自主库的binlog event，并解析成对应的数据,持续输出到管道。订阅过程中，需要根据前面的半同步开启状态决定是否发送ACK给主库
6. 消费管道的数据
## 2. serverless实现猜测
https://cloud.tencent.com/document/product/1003/81819
1. 随机数A/B：使用c.salt.用于密码加密
2. 保留字：使用c.reserved.用于保留字段，用于区分客户端类型（内部还是用户）
3. server层的改动：随机数B+保留字，用于代理客户端的鉴权；然后采用随机数A对用户密码进行鉴权
