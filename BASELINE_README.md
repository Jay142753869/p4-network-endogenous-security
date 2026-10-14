# 三模态原始演示项目运行说明

本演示项目展示 IPv4、IPv6 和源路由（Source Routing，SR）三种转发模态。三条路径如下：

- IPv4：`h1-s1-s11-s12-s2-h2`
- IPv6：`h1-s1-s21-s22-s2-h2`
- SR：`h1-s1-s31-s32-s2-h2`

本文件中的说明文字均使用中文；终端命令和程序原始输出仍保留英文，便于与实际运行结果逐项对照。

## 1. 材料内已完成的环境适配

本演示项目已针对课程统一使用的 `2026-Aug-01` P4 tutorials 镜像完成以下适配：

- `Makefile` 的编译和运行目标已指向正确路径。
- `mycontroller.py` 的默认 `--p4info` 路径已改为 `./build/polymorphic.p4.p4info.txtpb`。旧版 `2023-Feb-03` 镜像使用的文件名为 `./build/polymorphic.p4.p4info.txt`。
- `topo/topology.json` 已配置各主机的 IPv6 链路本地地址和静态邻居项。
- 项目内 `utils/p4_mininet.py` 已启用 IPv6。
- 材料内已经包含适配后的本地 `utils/`，无需另外下载或替换工具包。

## 2. 2026 版 utils 的 IPv6 适配原理

与 `2023-Feb-03` 镜像相比，`2026-Aug-01` 镜像中的大部分 IPv6 支持已经内置，差异如下：

| 文件 | 2023-Feb-03 镜像 | 2026-Aug-01 镜像 |
| --- | --- | --- |
| `utils/p4_mininet.py` | 需要将 `disable_ipv6=1` 改为 `disable_ipv6=0` | 仍需进行该修改；材料内已完成 |
| `utils/p4runtime_lib/convert.py` | 需要增加 IPv6 正则匹配及编码函数 | 已内置 IPv6 编解码支持，无需修改 |
| `utils/run_exercise.py` | 需要修改 `addHost()`，向主机传递 `ip6=` | 已能执行 `topology.json` 中的主机命令，无需修改 |
| `topo/topology.json` | 通过各主机的 IPv6 命令完成配置 | 继续使用相同方式；该文件不属于 `utils/` |

### 2.1 为什么 P4Info 后缀由 `.txt` 改为 `.txtpb`

P4Info 是文本格式的 Protocol Buffer 文件，用于描述 P4 表、动作和匹配键。较新的 p4c 已不推荐使用普通 `.txt` 后缀，改用含义更明确的 `.txtpb`。两者的内容格式相同，仅文件扩展名不同。因此，2026 版 `Makefile` 生成 `polymorphic.p4.p4info.txtpb`，`mycontroller.py` 也读取该文件。

### 2.2 IPv6 开关说明

原始 `P4Host.config()` 会通过以下设置禁用 IPv6：

```python
self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
```

材料内的 `utils/p4_mininet.py` 已将其改为：

```python
self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=0")
self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=0")
```

若自行从原始镜像重建项目而未完成该修改，`topology.json` 中的 `ip -6 addr add` 和 `ip -6 neigh add` 会提示 `IPv6 is disabled on this device`，随后 `ping6` 将出现 `100% packet loss`。

## 3. 编译并启动拓扑

打开终端 A，进入本 Demo 目录后执行：

```bash
make
```

`make` 会编译 P4 程序并启动 Mininet。镜像通常已经配置好运行环境；只有当前终端提示找不到 `p4c`、`simple_switch_grpc` 等命令时，才在该终端执行一次 `source ~/p4setup.bash`，然后重试。

## 4. 下发表项前的基线现象

控制器尚未下发表项时，IPv4 和 IPv6 均不应连通。在 Mininet 提示符中执行：

```text
mininet> pingall
*** Ping: testing ping reachability
h1 -> X
h2 -> X
*** Results: 100% dropped (0/2 received)

mininet> py h1.cmd('ping6 -c 3 fe80::5678%eth0')
3 packets transmitted, 0 received, 100% packet loss

mininet> py h2.cmd('ping6 -c 3 fe80::1234%eth0')
3 packets transmitted, 0 received, 100% packet loss
```

上述失败现象用于证明数据面尚未获得控制器表项，不表示实验环境故障。

## 5. 启动控制器并下发表项

保持终端 A 中的 Mininet 运行，另开终端 B，进入同一 Demo 目录后执行：

```bash
python3 mycontroller.py
```

控制器会为 IPv4 和 IPv6 转发下发表项。源路由所需的端口栈由发送脚本写入数据包，因此不依赖控制器生成路径。

## 6. 验证 IPv4 转发

回到终端 A 的 Mininet 提示符，执行：

```text
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2
h2 -> h1
*** Results: 0% dropped (2/2 received)
```

预期结果为双向连通且丢包率为 `0%`。

## 7. 验证 IPv6 转发

可任选以下一种方法；建议两种方法都执行并保存结果。

### 方法一：收发消息

在 Mininet 提示符中为 `h1` 和 `h2` 打开终端：

```text
mininet> xterm h1 h2
```

在接收端主机窗口启动接收程序：

```bash
python3 receive.py
```

在发送端主机窗口执行相应命令：

```bash
# h1 -> h2
python3 send.py fe80::1234 fe80::5678 "Hello P4!"

# h2 -> h1
python3 send.py fe80::5678 fe80::1234 "Hello P4!"
```

预期结果为接收端窗口显示发送的消息。

### 方法二：使用 ping6

在 Mininet 提示符中执行：

```text
mininet> py h1.cmd('ping6 -c 3 fe80::5678%eth0')
3 packets transmitted, 3 received, 0% packet loss

mininet> py h2.cmd('ping6 -c 3 fe80::1234%eth0')
3 packets transmitted, 3 received, 0% packet loss
```

实际时延会随运行环境变化，只需确认双向均收到 3 个响应且丢包率为 `0%`。

## 8. 验证源路由转发

在 Mininet 提示符中为 `h1` 和 `h2` 打开终端：

```text
mininet> xterm h1 h2
```

在接收端主机窗口启动接收程序：

```bash
python3 receive.py
```

在发送端主机窗口启动源路由发送程序，并按提示输入端口栈：

```text
# h1 -> h2
python3 send-sr.py 10.0.2.2
Type space separated port nums (example: "4 2 2 1","4 1 1 1") or "q" to quit: 4 2 2 1

# h2 -> h1
python3 send-sr.py 10.0.1.1
Type space separated port nums (example: "4 2 2 1","4 1 1 1") or "q" to quit: 4 1 1 1
```

预期结果为接收端收到消息。抓包时还可以观察 IP 首部中的 `ttl`，其数值会在每一跳递减。

## 9. 结束实验并清理环境

关闭 `h1`、`h2` 的 xterm，然后在 Mininet 提示符中退出：

```text
mininet> exit
```

回到终端 A 后执行：

```bash
make clean
```

若 Mininet 或 BMv2 进程未正常退出，可先执行 `make stop`，再执行 `make clean`。

## 10. 完成判据

同时满足以下结果即可认定原始三模态演示项目验证通过：

1. P4 程序编译成功，拓扑能够启动。
2. 控制器下发表项前，IPv4 和 IPv6 均不连通。
3. 控制器下发表项后，`pingall` 的丢包率为 `0%`。
4. IPv6 消息或 `ping6` 能够双向传输。
5. SR 使用推荐端口栈时能够双向传输消息。
