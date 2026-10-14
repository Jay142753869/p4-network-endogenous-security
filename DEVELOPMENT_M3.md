# 第二阶段开发报告：M3

本轮完成 M3 的入口识别、序号、CRC32、调度表及 P4Runtime multicast 配置，停止于 M3。
实现提交：**`d7284f6`**，前置版本：`154e6d9`。本报告在实现提交之后单独提交。

沿用 `.course-git/`，没有重复初始化仓库或改写历史：

```bash
git --git-dir=.course-git --work-tree=. show --stat d7284f6
git --git-dir=.course-git --work-tree=. log --oneline -5
```

## A. M3 实现的功能

已核对本轮指定的六个文件，并重读官方第二次实验指导 2.1–2.4、3.6–3.7。

Ingress 首先检查 `standard_metadata.parser_error`，错误时 `mark_to_drop()` 并立即退出，避免后续查表覆盖丢弃决定。
对已解析 PolyShim，检查 magic、内层 EtherType、direction 范围、modality_id 范围、内层头和保护数据有效性、固定长度以及外层模态的一致性；无效时丢弃。
没有重写 Parser。

调度需要同时满足：

- `ingress_port == 1`，Ethernet 有效且 EtherType 为 IPv4。
- IPv4、UDP、protected_data 都有效；没有 PolyShim、inner_ipv4、IPv6 或 SR 栈。
- IPv4 version=4、IHL=5、fragment offset=0、MF=0、保留 flag=0；允许 DF。
- IPv4 protocol=17、totalLen=44；UDP dport=5000、length=24。
- 实际帧长至少 58 字节，允许 Ethernet padding。
- 最后命中 `MyIngress.polymorphic_schedule` 的目的地址表项。

表未命中或普通非实验报文继续原有转发。UDP/5000 的其他长度不会调度；若声称有 16 字节却实际截断，Parser error 会导致丢弃。

命中后保存完整原 IPv4 到 `inner_ipv4`，使原 `hdr.ipv4` 无效，保留 UDP 和 protected_data，创建 PolyShim，计算共享 sequence/CRC，然后设置 `mcast_grp=10` 并退出 Ingress，避免再经过普通 IPv4 转发修改内层 TTL。

M3 中 `modality_id=0` 仅表示等待 M4 的暂存状态。没有生成 IPv4 protocol=253、IPv6 或 SR 外层。

## B. 修改文件与关键代码位置

| 文件 | 位置与作用 |
| --- | --- |
| polymorphic.p4:15 | multicast group 常量 |
| polymorphic.p4:143 | scheduled、packet_direction、sequence_number metadata |
| polymorphic.p4:301 | 双槽 32 位序号 register |
| polymorphic.p4:307 | start_polymorphic action |
| polymorphic.p4:312 | polymorphic_schedule 表 |
| polymorphic.p4:326 | 保存内层、分配序号、创建 PolyShim、CRC、触发复制 |
| polymorphic.p4:438 | parser_error、PolyShim 完整性与入口调度资格检查 |
| polymorphic.p4:517 | 原普通转发分支补充 header validity 检查 |
| mycontroller.py:27 | writeMulticastGroup，构造并写入 PRE entry |
| mycontroller.py:38 | writePolymorphicScheduleRule，与实际 P4Info 对齐 |
| mycontroller.py:208 | 只对 S1/S2 配置 group 和双向调度 |
| tests/check_m3.py | 编译产物解释、序号/CRC/PRE 模型和实际 protobuf 构造测试 |
| tests/check_m3_pcaps.py | 用户在真实运行后检查源网关三个出口的 M3 暂存报文 |
| evidence/m3/ | 实际编译、离线检查、P4Info、版本与哈希、socket 限制记录 |

Parser、原有转发 action/table 定义、Egress、checksum control、Deparser 均保持前置版本内容。
控制器原有 **18 条** ARP/IPv4/IPv6 配置调用及参数保持一致。
未修改 utils、拓扑、参考材料、发送接收脚本、实验三自动验收工具和预期结果。

## C. 序号 register 设计

`register<bit<32>>(2) sequence_register`，完整名称为 `MyIngress.sequence_register`。
槽 0 对应 direction=0，槽 1 对应 direction=1；每台交换机拥有独立寄存器状态。

BMv2 新建或重置流水线时，这两个槽初始为 0；保存的是“上一次分配值”。每次读出后执行 32 位加一，写回，并赋给 PolyShim：

```text
初始槽值 0 → 首包 sequence 1 → 2 → 3 → …
0xfffffffe → 0xffffffff → 0 → 1 → …
```

读、加、写在同一个 Ingress action 的 `@atomic` 块内。只有调度成功且 direction 合法才执行一次；普通包、表未命中、无效包和已封装包不消耗序号。
PRE 在 Ingress 之后复制，因此三份副本继承相同序号。Egress 没有 register 操作。

S1 使用本机槽 0，S2 使用本机槽 1；两者无需共享或同步。BMv2 初始为零的依据已核对本机 `stateful.cpp` 的 RegisterArray 构造与 `data.h` 的 `Bignum value{0}`，不是对所有 P4 硬件的通用初始化承诺。
状态不持久化；流水线重装或交换机重启会重新从 1 分配。完整 32 位空间循环后序号复用，后续 M5 需按方向与有限窗口管理状态。

## D. CRC32 字段与算法

调用 `v1model.hash`，算法为 `HashAlgorithm.crc32`。字段按下面的网络字节序连续拼接：

| 顺序 | 字段 | 位宽 |
| ---: | --- | ---: |
| 1 | hdr.inner_ipv4.srcAddr | 32 |
| 2 | hdr.inner_ipv4.dstAddr | 32 |
| 3 | hdr.inner_ipv4.protocol | 8 |
| 4 | hdr.udp.srcPort | 16 |
| 5 | hdr.udp.dstPort | 16 |
| 6 | hdr.protected_data.value | 128 |
| 合计 | 无额外 padding | **232 bit / 29 字节** |

本机 BMv2 固定 crc32 实现为 CRC-32/ISO-HDLC：poly=`0x04c11db7`（反射形式 `0xedb88320`）、初始余数=`0xffffffff`、输入/输出反射=true、final XOR=`0xffffffff`。
这些参数来自本机 `behavioral-model/src/bm_sim/calculations.cpp`，没有调用 custom CRC 配置。

P4 hash 的 `base=(bit<32>)0`，`max=(bit<64>)0x100000000`。
base/max 是 hash 输出范围参数，不是 CRC seed；使用 2^32 保留完整 32 位 CRC，避免 `max=0xffffffff` 把 CRC 恰为 `0xffffffff` 的结果错误取模成 0。

离线已检查编译后的 calculation 输入顺序和实际解释得到的 29 字节。参考向量：

```text
src=10.0.1.1 dst=10.0.2.2 protocol=17 sport=49152 dport=5000
data=ASCII "0123456789abcdef"
input_hex=0a0001010a00020211c000138830313233343536373839616263646566
Python/bitwise model CRC32=0x034c6fbb
```

TTL、IPv4 checksum、外层地址、MAC、SR 栈和 Ethernet padding 均不进入计算。
M5 必须对收到的实际内层字段，使用同样的字段顺序、位宽、算法和 base/max 重算 observed_crc，不能直接以 source_crc32 投票。

## E. multicast group 10 配置

数据面写 `standard_metadata.mcast_grp = POLY_MCAST_GROUP`，常量值为 10。
控制器使用课程本地库 `buildMulticastGroupEntry()` 和 `WritePREEntry()`，经 P4Runtime `WriteRequest` 的 `packet_replication_engine_entry` 写入：

| 交换机 | group_id | (egress_port, instance) |
| --- | ---: | --- |
| S1 | 10 | (2,1)、(3,2)、(4,3) |
| S2 | 10 | (2,1)、(3,2)、(4,3) |

两个 group 都先于调度表项安装。其余八台交换机没有新增 PRE 或调度规则。
instance 用于 PRE 副本编号；M4 必须按 `egress_port` 选择封装，不能把 instance 当作端口。
主机仍只发送一份原始报文。

## F. 双向调度实现

`MyIngress.polymorphic_schedule` 的三个 exact key 依次为 ingress_port（9 bit）、IPv4 dstAddr（32 bit）、UDP dstPort（16 bit）。
action 为 `MyIngress.start_polymorphic(packet_direction: bit<8>)`；默认 `NoAction`。

| 源网关 | 匹配入口 | 匹配目的 IP | UDP dport | direction |
| --- | ---: | --- | ---: | ---: |
| S1 | 1 | 10.0.2.2 | 5000 | 0 |
| S2 | 1 | 10.0.1.1 | 5000 | 1 |

控制器拒绝 0/1 以外的方向；数据面也在访问 register 前再次检查，避免错误配置导致越界。
普通 IPv4/IPv6/ARP/SR 规则及转发顺序保留，只有符合完整格式并命中调度表的包进入准备路径。

## G. P4 编译结果

| 子模块 | 实际命令 | 退出码 |
| --- | --- | ---: |
| M1/M2 起点 | make build | 0 |
| 入口检查与调度表 | make build | 0 |
| 序号与 inner 保存，首次 | make build | 0，出现 header validity 警告 |
| 补充普通分支 validity 后 | make build | 0 |
| CRC32 | make build | 0 |
| 控制器完成后的最终版本 | make build | 0 |

所有步骤均实际执行 P4_16/v1model/BMv2 编译，完整输出保存在 `evidence/m3/build-*.log`。
序号子模块首次出现的三条 potentially invalid IPv4 警告已通过显式 validity 条件修正，未通过删除原转发功能消除。
最终只剩原有五项 unused ARP 常量警告，以及导入文件时间戳超前产生的 Make future time / Clock skew 提示；没有 error。
已核对实际生成的 P4Info 表名、key 位宽/类型和 action 参数，保存于 `p4info-contract.txt`。

预装工具版本：p4c 1.2.5.15（cdd7205767）、BMv2 1.15.4-883d4eae、Mininet 2.3.1b4。
沿用现有课程环境和 2026-Aug-01 材料接口，未升级、替换工具链或修改系统策略。

## H. Python 静态检查结果

实际执行并通过，退出码 0：

```bash
python3 -m py_compile mycontroller.py tests/check_m3.py tests/check_m3_pcaps.py
git --git-dir=.course-git --work-tree=. diff --check
```

`verification.txt` 还记录了源码/产物 SHA256，以及 Parser、原转发定义、Egress、checksum、Deparser 和控制器原有 18 条调用保持一致的检查。

## I. 实际运行测试情况

### 当前会话实际完成

- `python3 tests/check_m3.py`：**9 组测试通过**，组内包含逐项资格变更、普通 UDP、不完整包、三模态双向防重调度、无效 PolyShim、连续序号、回绕、方向槽/交换机独立性、CRC 字段顺序与稳定字段、CRC 边界值、PRE 模型、真实 protobuf 序列化及双网关配置。
- `python3 tests/check_m2_parser.py`：原 **34 个离线 Parser 用例通过**。
- 抓包检查工具只用明确标注的合成 pcap 测过正常与缺包分支，未使用或生成冒充真实交换机的抓包证据。
- 首次 M3 测试曾因模型未安装普通 IPv6 路由、却预期不丢弃而失败；已修正为核对原 IPv6 表的默认 drop 行为，首次日志也保留。

以上是 **Python 对编译 JSON 的解释、CRC/PRE 模型及 P4Runtime 消息构造**，没有启动 BMv2，也没有把请求发送到交换机。
沙箱实际探测到创建 AF_INET socket 被拒绝；AF_UNIX socket 创建允许，但未尝试绑定。见 `runtime-status.log`。
本轮没有启动 Mininet，没有取得真实 PRE 复制、CRC extern 执行、普通网络回归或三模态端到端结果。

### 在普通 Ubuntu 终端待执行的完整命令

以下命令是待执行步骤，预期不是本轮测试结果。先在终端 A 启动本项目的新拓扑：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
make build
python3 tests/check_m3.py
make
```

终端 B 安装流水线、原有路由、PRE 和双向调度：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
python3 mycontroller.py
```

控制器无异常退出后，在终端 A 的 Mininet 提示符依次执行（不粘贴 `mininet>` 前缀）：

```text
pingall
h1 ping6 -c 2 fe80::5678%eth0
h2 ping6 -c 2 fe80::1234%eth0
h1 ip neigh flush dev eth0
h1 ping -c 2 10.0.2.2
h1 sh -c 'timeout 60 python3 -u receive.py > /tmp/m3-h1-ordinary.log 2>&1 &'
h2 sh -c 'timeout 60 python3 -u receive.py > /tmp/m3-h2-ordinary.log 2>&1 &'
h1 sh -c "printf '4 2 2 1\nq\n' | python3 send-sr.py 10.0.2.2"
h2 sh -c "printf '4 1 1 1\nq\n' | python3 send-sr.py 10.0.1.1"
h1 cat /tmp/m3-h1-ordinary.log
h2 cat /tmp/m3-h2-ordinary.log
h1 python3 send-poly.py 10.0.2.2 m3-first
h1 python3 send-poly.py 10.0.2.2 m3-second
h2 python3 send-poly.py 10.0.1.1 m3-reverse
```

发送次数预期为正向 2、反向 1。此时主机不应作为多模态最终成功接收的判据。
在普通终端 C、保持拓扑仍在运行时，读取源端寄存器与调度表：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
printf 'register_read MyIngress.sequence_register\ntable_dump MyIngress.polymorphic_schedule\n' | simple_switch_CLI --thrift-port 9090
printf 'register_read MyIngress.sequence_register\ntable_dump MyIngress.polymorphic_schedule\n' | simple_switch_CLI --thrift-port 9091
```

按本次全新启动且没有其他实验输入，预期 S1 register 为 `[2,0]`，S2 为 `[0,1]`。
然后在终端 A 执行 `exit`，使交换机关闭并刷新抓包；在普通终端 C 检查三个源出口：

```bash
python3 tests/check_m3_pcaps.py --direction 0 --expect 2 pcaps/s1-eth2_out.pcap pcaps/s1-eth3_out.pcap pcaps/s1-eth4_out.pcap
python3 tests/check_m3_pcaps.py --direction 1 --expect 1 pcaps/s2-eth2_out.pcap pcaps/s2-eth3_out.pcap pcaps/s2-eth4_out.pcap
tcpdump -nn -e -xx -r pcaps/s1-eth2_out.pcap
tcpdump -nn -e -xx -r pcaps/s1-eth3_out.pcap
tcpdump -nn -e -xx -r pcaps/s1-eth4_out.pcap
```

检查工具按 sequence 对照三个出口、重算内层 CRC，并核对完整副本字节；不会将“源出口复制成功”描述成“端到端通信成功”。
保存真实结果后再清理：

```bash
mkdir -p evidence/m3-runtime
cp pcaps/s1-eth2_out.pcap pcaps/s1-eth3_out.pcap pcaps/s1-eth4_out.pcap evidence/m3-runtime/
cp pcaps/s2-eth2_out.pcap pcaps/s2-eth3_out.pcap pcaps/s2-eth4_out.pcap evidence/m3-runtime/
make stop
make clean
```

## J. 尚未解决的问题

1. 真实 BMv2/PRE 执行及普通 IPv4/IPv6/ARP/SR 连通性回归仍待上述终端验证。离线解释器只支持本阶段已用操作，并不能证明运行时行为或并发正确性。
2. M3 输出仍是 `Ethernet / PolyShim(mode=0) / inner IPv4 / UDP / data` 暂存线序；EtherType 保留输入值，没有完成外层封装，不能作为合法三模态链路报文。Wireshark 按 EtherType 解码可能显示异常，抓包工具因此显式按 M3 暂存偏移读取。
3. M4–M6 未实现；不能要求现有 Parser 在下一跳正确接收 M3 暂存副本，也不能宣称三条路径贯通、完成裁决或主机只收到一份。
4. 已封装报文的目的网关截获仍留在后续阶段。原 SR 终止逻辑假设栈后为普通 IPv4，后续必须在该逻辑之前处理 PolyShim 副本，避免错标 EtherType 或把内部报文送到主机。
5. 序号重启/回绕后的复用、有限窗口、迟到副本与方向隔离需要在 M5 状态设计中处理。本轮没有添加裁决状态。

## K. M4 开发建议

只对 `meta.scheduled==1` 的 multicast 副本，在 Egress 根据只读 `standard_metadata.egress_port` 选择模态：2→IPv4/id1，3→IPv6/id2，4→SR/id3。
保留已生成的 sequence/source_crc32、原内层 IPv4、UDP 和数据；不要在 Egress 重新分配序号或重新计算源 CRC。

从当前无效的 `hdr.ipv4` 开始构建真正外层；分别设置有效性、EtherType、外层地址、TTL/hopLimit、protocol/nextHdr=253、长度和 checksum。
固定输入下 IPv4 外层 totalLen=78，IPv6 外层 payLoadLen=58；SR 外层按方向写官方端口栈，栈后直接接 PolyShim。
普通报文必须跳过这一封装分支。

每种模态单独编译，先检查源出口，再观察对端入口；M5/M6 尚未接入时，目的端不得把封装副本当普通主机报文输出。
三条实际路径核对通过之前，不创建 `class2-multicast` 完成标签。

本轮到此停止，等待下一步指令。
