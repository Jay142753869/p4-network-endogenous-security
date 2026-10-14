# M5 开发报告：目的网关数据平面 2/3 多数裁决

本轮完成 M5 代码、分步编译及离线验证。**尚未通过 M5 真实 BMv2 运行验收。** M6 未实现，所有到达目的网关的封装副本（包括形成多数的副本）仍安全丢弃。

依据 `STUDENT_TODO.md`、第三次实验指导 PDF、`reference/experiment3/adjudication_state.p4.inc` 和 `adjudication_model.py` 实现；核对了现有 counter 读取、反馈和验收工具，未修改其预期。官方 Python 模型只用于理解状态转移，真实 P4 的 CRC 继续采用 M3 固定的 232 bit 输入。

## A. M5 实现概述

- 在现有目的角色表接入 `MyIngress.adjudicate_polymorphic`，只在 S2 正向、S1 反向执行。
- 实际接收字段计算 observed CRC；以三个不同模态的 CRC 形成 2/3 多数。
- 新增 1024 项窗口、完整序号标签、方向保护、模态去重、明确终局状态及统计。
- 首次形成多数的当前副本设置 `meta.adjudication_accept=1`；该标记供 M6 使用，本轮仍 drop。
- 未重构 M1–M4：Parser、M3 source CRC/sequence/PRE、M4 Egress、普通路由和校验和逻辑保持原实现。

关键位置以实现提交中的代码为准：

| 文件及位置 | 修改内容 |
| --- | --- |
| `polymorphic.p4:26` | 1024 项窗口与三种状态常量 |
| `polymorphic.p4:155` | 胜出标记及本包裁决工作 metadata |
| `polymorphic.p4:330` | slot 状态和方向高水位 register |
| `polymorphic.p4:347` | 官方名称、尺寸的三个 counter |
| `polymorphic.p4:407` | observed CRC、原子窗口事务、候选、裁决、统计 |
| `polymorphic.p4:552` | 原目的表增加裁决 action，匹配字段不变 |
| `polymorphic.p4:649` | 每包清零 accept；目的命中后保留标记并安全丢弃 |
| `mycontroller.py:56` | 精确目的规则改为调用裁决 action |
| `mycontroller.py:227` | 网关 default 继续 hold，S1/S2 三条精确角色规则不变 |
| `tests/check_m3.py:31` | 编译 JSON 离线执行器支持多 register、counter 和条件跳转 |
| `tests/check_m4.py:36` | 离线交换机支持跨包状态；目的 action 期望更新为 M5 |
| `tests/check_m5.py:89` | 15 组 M5 测试，包含多种子情形 |
| `class3/state-design.txt` | 状态转移、原子性和边界的独立设计记录 |
| `evidence/m5/` | 完整编译日志、离线结果、P4Info、静态核对与运行限制 |
| `evidence/m4-runtime/` | 用户提供的真实 M4 pcap 及本轮原工具复查记录 |

## B. observed_crc 计算

P4 action 对当前收到的 header 字段调用：

```p4
hash(meta.vote_observed_crc, HashAlgorithm.crc32, (bit<32>)0,
     { hdr.inner_ipv4.srcAddr,
       hdr.inner_ipv4.dstAddr,
       hdr.inner_ipv4.protocol,
       hdr.udp.srcPort,
       hdr.udp.dstPort,
       hdr.protected_data.value },
     (bit<64>)0x100000000);
```

输入按网络字段顺序拼接为 `32+32+8+16+16+128=232 bit=29 byte`，没有 padding 字段。与 M3 的 source CRC hash 算法、base、max 完全一致；M3 代码未改。

本 BMv2 的 `crc32` 对应 CRC-32/ISO-HDLC：多项式 `0x04c11db7`（反射形式 `0xedb88320`），初始余数 `0xffffffff`，输入/输出反射，最终 XOR `0xffffffff`；离线对照使用 `zlib.crc32`。P4 的 base=0、max=2^32 是 hash 输出范围参数，不是把 CRC 内部初始余数改为 0。

裁决 action **不读取 source_crc32**，投票只比较 observed CRC。外层地址、MAC、TTL、checksum、SR 栈均不参与；inner TTL/checksum 同样不参与。离线测试验证改变 source CRC 不改变投票，保留相同 source CRC 而篡改实际 protected_data 会改变 observed CRC，并将对应模态判为 bad。

## C. register 状态设计与原子性

每台目的交换机独立保存以下状态，不在 S1/S2 之间共享：

| register | 位宽 | 项数 | 含义 |
| --- | ---: | ---: | --- |
| slot_valid | 1 | 1024 | 空槽与合法 sequence=0 的区分 |
| slot_direction | 8 | 1024 | 槽所属方向，拒绝错误角色混用 |
| seq_tag | 32 | 1024 | 完整序号 |
| crc_candidate_1/2 | 各 32 | 各 1024 | 最多两个不同 CRC |
| mode_candidate_1/2 | 各 8 | 各 1024 | 候选所属模态，供追溯统计 |
| seen_modes | 8 | 1024 | 低三位记录已经到达的模态 |
| candidate_counts | 2 | 1024 | 不同 CRC 候选数 0/1/2 |
| decided | 1 | 1024 | 终局标记 |
| decision_status | 2 | 1024 | 0 未决定、1 多数、2 无多数 |
| decided_crc | 32 | 1024 | 多数 CRC，等价 winner_crc |
| latest_sequence | 32 | 2 | 按 direction 索引的序号高水位 |
| latest_valid | 1 | 2 | 高水位有效性 |

S2 只管理 direction=0，S1 只管理 direction=1。两个方向在不同 BMv2 实例中独立运行；本实现不是单台交换机承载两个独立的 1024 项方向窗口。额外的 slot_direction 用于误配置时拒绝跨方向覆盖。

所有 14 个 M5 register 数组的读取、序号判断、初始化、去重、终局判断、统计触发、写回，都放在裁决 action 的一个 `@atomic` 块中。p4c 成功编译为**同一 action 内的 139 条 primitive**，通过 `_jump` / `_jump_if_zero` 表达分支，没有跨 action 的读改写事务。

核对本机 `/home/p4/src/behavioral-model/src/bm_sim/actions.cpp`：`ActionFnEntry::operator()` 在 `execute(pkt)` 前取得该 action 访问的 register 数组锁，并在完整 action 返回后释放。因此此目标上高水位、slot 和统计触发受同一事务保护；其他 action 没有访问这些 M5 数组。源码片段及编译结构见 `evidence/m5/atomicity-evidence.txt`。

这是本机目标的静态原子性依据，**不是实际并发压力测试结果**。数组级锁也会串行化不同 slot 的裁决，吞吐性能尚未测量；不泛化为其他硬件目标的保证。

## D. slot 初始化与复用

`slot = sequence_number & 1023`。先检查方向高水位，再允许空槽/不同标签槽初始化，避免旧包重新开启或覆盖已复用状态。

32 bit 模运算中，令 `delta=current-latest`、`age=latest-current`：

- 首次有效包允许任意初始序号。
- `0 < delta < 2^31` 认为序号更新，允许接纳并推进高水位。
- `delta=0` 属于同组，使用已有 seen/decision 状态。
- 较旧序号只在 `age<1024` 时允许乱序到达；`age>=1024` 丢弃，即使对应槽尚为空。
- 恰好相差 `2^31` 无法判定前后，拒绝。

通过检查后，仅在 slot 无效或 seq_tag 不同的情况下清零候选、seen、终局和 winner，设置新标签、方向和 valid。例：1→1025 复用槽 1 后，迟到的 1 不得回写状态、统计或高水位。

`slot_valid` 保证 sequence=0 可用；`0xffffffff→0` 按上述模运算推进。要求有效推进/滞留跨度小于 2^31，无法仅凭 32 bit 序号识别跨完整序号空间的旧 epoch。

冷启动/流水线重装会清零 register/counter。若只重启源端而目的端保留旧状态，低序号可能被判重复或过旧，需协调建立新会话/重置；本轮没有自动 epoch 协议。

## E. seen_modes 处理

mode1 对应 bit0=1，mode2 对应 bit1=2，mode3 对应 bit2=4。先验证包结构及目的角色，再在原子事务内检查该 bit。

重复模态直接走安全丢弃：不写任何 M5 register、不增加候选、不推进高水位、不写 counter、不产生 accept。即使重复副本携带不同 protected_data，也不能污染已记录的候选。

## F. 多数裁决状态机

每包开始 `adjudication_accept=0`，不假设任何模态先到。

| 当前状态/新 observed CRC | 转移 | accept |
| --- | --- | ---: |
| 未决定，无候选 | 保存候选 1 及模态 | 0 |
| 未决定，仅候选 1，相同 CRC | 多数，winner=当前 CRC | 1 |
| 未决定，仅候选 1，不同 CRC | 保存候选 2 及模态 | 0 |
| 未决定，两候选，匹配任一个 | 多数，winner=当前 CRC | 1 |
| 未决定，两候选，均不匹配 | 无多数，no_majority 加 1 | 0 |
| 已多数，新模态 | 只与 winner 比较并统计 | 0 |
| 已终局，重复模态 | 不改状态和统计 | 0 |

因此 AAA 在第二份形成多数；AAB 在第二份形成多数，第三份 B 为 bad；ABB 在第三份形成多数，先前 A 补记 bad；ABC 三份各异，没有 accept；AA 缺第三份仍可形成多数。`A(mode1),A(mode1),B(mode2)` 只有两个不同模态、两个不同 CRC，不能形成多数。

`decided` 与 `decision_status` 同步写入；决定分支由 status 控制，避免把无多数当成可输出决定。合法 winner CRC=0 通过 status 与无多数区分。

## G. 迟到与重复副本

首次多数形成时当前副本才获得一次 accept；后续第三个不同模态只补计一次 good/bad。重复副本没有第二次 accept，不能反复增加统计。三份各异只有进入无多数的那一次增加 no_majority。

允许窗口内乱序与多个 sequence 交错；窗口外迟到第三份被丢弃，不再补记该历史组的统计。这是有限窗口约束，不承诺无限等待或永久去重。

## H. good/bad/no_majority 统计

接口完全采用官方名称与规格：

```p4
counter(5, CounterType.packets) good_count;
counter(5, CounterType.packets) bad_count;
counter(1, CounterType.packets) no_majority_count;
```

good/bad 仅使用模态索引 1、2、3；0、4 保持未使用。no_majority 使用索引 0。

多数形成前不提前判断 good/bad。形成多数时，回看已保存的一个或两个候选，逐个与 winner 比较补记，再记当前匹配副本 good。多数后到达的第三个新模态与 winner 比较记一次。不存在的模态不因缺失记 bad。

| 三个模态的内容 | good[1,2,3] | bad[1,2,3] | no_majority[0] |
| --- | --- | --- | ---: |
| A,A,A | 1,1,1 | 0,0,0 | 0 |
| B,A,A（mode1 错误） | 0,1,1 | 1,0,0 | 0 |
| A,缺失,A | 1,0,1 | 0,0,0 | 0 |
| A,B,C | 0,0,0 | 0,0,0 | 1 |

官方 `read-counters.py`、`evaluate-counters.py` 保持不变。离线测试实际构造 P4Runtime ReadRequest/Response，核对 counter ID、索引、packet_count 与反馈分类；传输使用无 socket 的 stub，不能称为真实 gRPC 读取成功。

## I. 控制器接口修改

保留 `MyIngress.polymorphic_destination` 的三个 exact key：`ingress_port`、`hdr.poly.direction`、`hdr.poly.modality_id`。精确规则 action 从 hold 改为 `MyIngress.adjudicate_polymorphic`，无额外 action 参数。

- S2：direction=0，(port,mode) 为 (2,1)、(3,2)、(4,3)。
- S1：direction=1，同样三对入口/模态。
- 两端网关 default 继续 `hold_polymorphic`；缺规则、错误方向、端口或模态不得绕过裁决。
- 中间交换机没有目的角色规则，继续按既有普通路由转发。
- 源端调度表、start action、两个源方向序号、232 bit source CRC、group10/PRE 及全部原路由调用参数未变。

P4Info 实际核对：目的表 ID=40492749；裁决 action ID=17760844；good/bad/no_majority counter ID 分别为 306155069、315541448、302757400，尺寸 5/5/1，单位 PACKETS。完整接口见 `evidence/m5/p4info-contract.txt`。

## J. P4 编译与 Python 静态检查

按用户指定步骤实际逐项执行 `make build`，以下各阶段退出码均为 0，完整输出保存在 `evidence/m5/build-*.log`：

| 日志编号 | 编译阶段 |
| --- | --- |
| 00 | M4 基线 |
| 01 | register 声明 |
| 02 | observed CRC |
| 03 | 窗口与初始化 |
| 04 | seen bitmap |
| 05 | 候选 CRC |
| 06 | 多数状态机 |
| 07 | good/bad/no_majority |
| 08 | 保持既有 metadata 编译名称的扁平工作字段 |
| 09 | 完整最终实现 |
| 10 | 注释校正后的最终编译 |

早期尚未使用的声明有 unused 警告，后续实现后消除；最终只剩基线已有的五个 ARP 常量 unused 警告。make 还报告导入的 `utils/Makefile` 时间在未来及 clock skew，日志中 p4c 编译命令实际执行且退出成功；未改系统时间或该文件。没有 atomic 不支持警告。

工具版本保持：p4c 1.2.5.15（cdd7205767）、BMv2 1.15.4-883d4eae、Mininet 2.3.1b4；未升级工具链。

以下检查实际通过：

```bash
python3 -m py_compile mycontroller.py tests/check_m3.py tests/check_m4.py tests/check_m5.py
git --git-dir=.course-git --work-tree=. diff --check
```

`evidence/m5/verification.txt` 保存版本、哈希及 M1–M4 区域不变核对。全局 tutorials/utils 未修改；项目 utils、官方材料、参考文件、官方验收/统计工具也未修改。

## K. 离线测试结果

实际通过：

| 命令 | 结果 |
| --- | --- |
| `python3 tests/check_m5.py` | 15 组通过，包含多种子情形 |
| `python3 tests/check_m4.py` | 8 组通过 |
| `python3 tests/check_m3.py` | 9 组通过 |
| `python3 tests/check_m2_parser.py` | 34 项通过 |

M5 测试解释 **p4c 生成的 JSON action/控制流**，模拟 Python CRC、register、counter；没有用另写的 Python 投票函数替代编译后的裁决逻辑。但这仍是离线解释执行，不是 BMv2 运行，也不能证明真实调度并发。

覆盖用户要求的全部类别：AAA/AAB/ABB/ABC/缺失、重复且数据不同、六种模态排列、决定后迟到、多个序号交错、连续 1030 个序号、slot1/1025 复用、旧包冲突、窗口 1023/1024 边界、半序空间拒绝、32 bit 回绕、方向和角色隔离、29 byte CRC 顺序、篡改检测、good/bad 补记、no_majority 恰好一次、普通 IPv4/IPv6/SR 不改变裁决状态、M6 前不得泄漏封装到主机。

另外把已归档的真实 M4 目的入口 pcap 输入 JSON 离线执行器：正向两个、反向一个序号分别产生两个/一个 accept 标记和每模态 2/1 次 good。**输入来源真实不等于本次执行是 BMv2；这项明确属于离线重放。**

M4 回归最初有一项静态源码定位检查因新增 action 改变边界而失败（ValueError）；保留 `m4-regression-initial.log`。改为正确的源码区段边界后 8 项通过，未放宽转发行为或官方验收预期。M5 的 action 范围检查进一步使用下一个 action 声明定位，避免依赖注释。

## L. 真实运行测试情况与普通 Ubuntu 验证命令

### 已有 M4 证据

用户提供的 52 份真实 pcap 已归档到 `evidence/m4-runtime/`，本轮使用未修改的 `tests/check_m4_pcaps.py` 对 source/full 两范围、正反两方向实际复查，全部通过：

| 方向 | 原始输入数 | sequence / source_crc32 |
| --- | ---: | --- |
| 正向 | 2 | 1 / 0xd4c4087e；2 / 0x71960faa |
| 反向 | 1 | 1 / 0xf1539cb0 |

普通 IPv4 pingall 和 IPv6 正向通过属于用户报告；**IPv6 反向、普通 SR 双向真实回归尚待补充。** 此归档只证明 M4 既有路径，不是 M5 状态机运行证据，也不代表 M6 还原。

### 本轮 M5 真实运行状态

实际探测 AF_INET socket 创建失败：`[Errno 1] Operation not permitted`，见 `evidence/m5/runtime-status.log`。因此未启动本轮 BMv2/Mininet，未实际读取 M5 register/counter，未产生 M5 真实 pcap；未修改 AppArmor、工具链或使用权限绕过。

### 待在普通 Ubuntu 终端执行

以下为待执行命令，不是本轮结果。使用课程环境和新的拓扑/流水线，保证 state/counter 从零开始。不要在旧拓扑仍运行时启动第二套；不要用官方 M6 端到端接收要求判断本阶段。

终端 A：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
mkdir -p evidence/m5-runtime
set -o pipefail
git --git-dir=.course-git --work-tree=. rev-parse HEAD > evidence/m5-runtime/revision.txt
make build 2>&1 | tee evidence/m5-runtime/build.log
make 2>&1 | tee evidence/m5-runtime/mininet.log
```

终端 B，待十台交换机启动后：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
set -o pipefail
python3 mycontroller.py 2>&1 | tee evidence/m5-runtime/controller.log
```

确认控制器成功安装流水线和规则后，在终端 A 的 Mininet 提示符执行（不要输入提示符文字）：

```text
h1 ip -4 neigh flush dev eth0
h2 ip -4 neigh flush dev eth0
pingall
h1 ping6 -c 2 fe80::5678%eth0
h2 ping6 -c 2 fe80::1234%eth0
h1 sh -c 'timeout 60 python3 -u receive.py > /tmp/m5-h1-ordinary.log 2>&1 &'
h2 sh -c 'timeout 60 python3 -u receive.py > /tmp/m5-h2-ordinary.log 2>&1 &'
sh sleep 1
h1 sh -c "printf '4 2 2 1\nq\n' | python3 send-sr.py 10.0.2.2"
h2 sh -c "printf '4 1 1 1\nq\n' | python3 send-sr.py 10.0.1.1"
sh sleep 1
h1 cat /tmp/m5-h1-ordinary.log
h2 cat /tmp/m5-h2-ordinary.log
h1 python3 send-poly.py 10.0.2.2 m5-forward-1
h1 python3 send-poly.py 10.0.2.2 m5-forward-2
h2 python3 send-poly.py 10.0.1.1 m5-reverse-1
sh sleep 2
```

SR 必须在相对端接收日志中看到对应 UDP/4321 数据；仅有发送端打印不算通过。清邻居命令只清 IPv4，保留拓扑已配置的 IPv6 静态邻居。每次 send-poly 应只有一条 POLY_SEND：正向共两份原包、反向共一份，PRE 负责复制。随机 UDP 源端口会使 CRC 与历史数值不同。

拓扑保持运行，终端 C：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
set -o pipefail
python3 read-counters.py 2>&1 | tee evidence/m5-runtime/counters.log
python3 evaluate-counters.py evidence/m5-runtime/counters.log | tee evidence/m5-runtime/feedback.log
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\nregister_read MyIngress.slot_valid 1\nregister_read MyIngress.seq_tag 1\nregister_read MyIngress.seen_modes 1\nregister_read MyIngress.decided 1\nregister_read MyIngress.decision_status 1\nregister_read MyIngress.decided_crc 1\nregister_read MyIngress.latest_sequence\n' | simple_switch_CLI --thrift-port 9090 | tee evidence/m5-runtime/s1-state.log
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\nregister_read MyIngress.slot_valid 1\nregister_read MyIngress.seq_tag 1\nregister_read MyIngress.seen_modes 1\nregister_read MyIngress.decided 1\nregister_read MyIngress.decision_status 1\nregister_read MyIngress.decided_crc 1\nregister_read MyIngress.slot_valid 2\nregister_read MyIngress.seq_tag 2\nregister_read MyIngress.seen_modes 2\nregister_read MyIngress.decided 2\nregister_read MyIngress.decision_status 2\nregister_read MyIngress.decided_crc 2\nregister_read MyIngress.latest_sequence\n' | simple_switch_CLI --thrift-port 9091 | tee evidence/m5-runtime/s2-state.log
```

Thrift 端口按本工程创建顺序 S1=9090、S2=9091；若启动日志给出不同端口，以日志为准。

从零开始的上述无故障输入，**预期而非本轮实测**：S2 三个 mode_good 均为 2，S1 均为 1；所有 bad=0、no_majority=0。S2 slot1/2 标签为 1/2，S1 slot1 标签为1；seen=7、decided=1、decision_status=1，winner 应等于对应真实入口包的 232 bit CRC。latest_sequence 的 S2 索引0为2、S1索引1为1。register 不能直接显示已离开流水线的 metadata accept，因此不能只凭一个 register 推断实际输出次数。

终端 A 执行 `exit` 正常关闭拓扑、刷新 pcap，**不要先执行 make clean**。终端 C：

```bash
python3 tests/check_m4_pcaps.py --direction 0 --scope source --expect 2 2>&1 | tee evidence/m5-runtime/source-forward.log
python3 tests/check_m4_pcaps.py --direction 1 --scope source --expect 1 2>&1 | tee evidence/m5-runtime/source-reverse.log
python3 tests/check_m4_pcaps.py --direction 0 --scope full --expect 2 2>&1 | tee evidence/m5-runtime/path-forward.log
python3 tests/check_m4_pcaps.py --direction 1 --scope full --expect 1 2>&1 | tee evidence/m5-runtime/path-reverse.log
cp pcaps/*.pcap evidence/m5-runtime/
cp /tmp/m5-h1-ordinary.log /tmp/m5-h2-ordinary.log evidence/m5-runtime/
python3 tests/check_m4_pcaps.py --pcap-dir evidence/m5-runtime --direction 0 --scope full --expect 2
python3 tests/check_m4_pcaps.py --pcap-dir evidence/m5-runtime --direction 1 --scope full --expect 1
```

full 检查涵盖源输入、三出口、s11/s12、s21/s22、s31/s32 的逐跳入/出口、目的三入口，以及目的主机端口没有封装/未经还原数据泄漏。它本身只核对路径与隔离，**不能单独证明 M5 多数判断**，必须结合本次原生 counter/register 输出和记录的实现版本。

以上无故障命令不会验证真实篡改、重复、无多数或并发；这些目前仅有离线覆盖，后续需在授权的真实测试阶段补证。本轮不部署故障注入，不运行实验三五场景自动验收，不要求 receive-poly 收到还原包，不创建任何完成标签。

## M. 当前限制

1. M5 原生 BMv2 状态行为与真实并发尚未验证，不能据离线通过宣布实验三运行验收成功。
2. IPv6 反向及普通 SR 双向仍缺真实回归结果；上面的命令供补测。
3. 有限 1024 窗口不补计窗口外迟到第三份；32 bit 模比较有半序空间/epoch 假设，源独立重启需协调处理。
4. 只有一个副本或两份 CRC 不同且第三份缺失时保持未决定，没有定时器或超时无多数判定。
5. CRC 用于课程内容一致性检测，存在碰撞，也没有认证序号/方向/模态来源；不承诺抵抗恶意伪造全部副本。
6. 数组锁粒度对性能有影响；未测吞吐，未实现跨设备共享状态或持久化。
7. M6 未实现，预期目的主机收到零份受保护还原数据；这是明确的阶段边界。

## N. M6 接入方案

在目的角色表命中后的当前 hook，以 `meta.adjudication_accept==1` 为唯一允许还原的分支：去除当前有效外层与 PolyShim，从独立 inner_ipv4 恢复原 IPv4 视图，配套有效性、EtherType、主机 MAC、出口和 checksum 处理。其他副本保持 hold/drop，不再进入普通路由或 SR 终结分支。

不重新分配序号、不重新计算 source CRC、不改变本轮状态机和计数语义；特别是已决定后的第三份即便 good，也不能第二次还原输出。M6 阶段再添加真实“每序号最多一份还原输出”的主机端验收，本轮没有实现这些操作。

## O. Git commit

继续使用 `git --git-dir=.course-git --work-tree=.`，保留既有 M1–M4 历史：

- `cc9c1cd`：归档用户提供的真实 M4 抓包，记录原工具实际复查及普通回归缺口。
- `1f078862bc09bcd9ed8f3f2f0f133116ae136d5e`：M5 P4、控制器、离线测试、状态设计与编译/检查证据。
- `4076af0`：静态 action 范围检查改用 action 声明边界，重新通过 15 组 M5 检查；是本报告对应的最新实现/测试提交。

本报告单独提交，避免在报告内递归写入自己的提交哈希。未创建 `class3-adjudication` 标签，未重写既有历史。完成本轮 M5 后停止，等待下一步指令。
