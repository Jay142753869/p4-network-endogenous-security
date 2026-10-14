# M6 开发报告：目的网关透明还原

M6 代码、逐步编译和离线回归已完成。**本轮尚未通过 M6 真实 BMv2 运行验收。** 沙箱实际创建 AF_INET socket 被拒绝，没有启动本轮 Mininet，也没有产生 M6 真实抓包。下文真实验收命令均为待用户在普通 Ubuntu 终端执行的步骤。

本轮只接入目的网关透明还原；不实现故障注入，不修改官方综合验收工具或预期，不运行五场景综合验收，不创建完成标签。

## A. 依据与前置证据

已阅读现有 P4、控制器、`DEVELOPMENT_M5.md`、`class3/state-design.txt`、`STUDENT_TODO.md`、官方第三次实验指导，以及 `receive-poly.py`、`run-poly-tests.py`。官方要求在首次多数的当前副本上恢复普通 IPv4，重算 checksum，后续副本只统计而不再次输出。

用户提供的 M5 真实无故障材料已单独归档到 `evidence/m5-runtime/`：

| 对象 | 真实材料中的结果 |
| --- | --- |
| S2 | 三个模态各 good=3、bad=0、no_majority=0 |
| S1 | 三个模态各 good=1、bad=0、no_majority=0 |
| S2 sequence 1 | seq_tag=1、seen_modes=7、decision_status=1、decided_crc=1853104259=0x6e742083 |

本轮实际重新读取 52 份原始 pcap，使用未修改的 M4 完整路径检查器，正向3份原始输入、反向1份原始输入均通过；正向 sequence 1 的 CRC 与上述 register 日志一致。原始 counter/register 日志、来源说明、复查输出及 SHA256SUMS 均保留。

这些是 **M5 前置证据**，没有 M6 还原输出，不能用作本轮 M6 真实验收结果。普通 IPv6 反向和 SR 双向仍缺补充的真实通过结论，本报告不把离线回归写成全部普通协议实测通过。

## B. 代码修改与控制流

新增 `MyIngress.restore_polymorphic()`，调用位置严格位于目的角色表命中之后：

```p4
if (polymorphic_destination.apply().hit) {
    if (meta.adjudication_accept == 1) {
        restore_polymorphic();
    } else {
        hold_polymorphic();
    }
}
```

只有已经通过原有结构校验、匹配目的网关精确规则、且 M5 对当前副本首次形成多数时，才会进入还原。首份、不同 CRC 的第二份、重复模态、已决定后的第三份、无多数、过旧序号继续 drop。

还原 action 末尾 `exit`，结束 Ingress：不能再次进入源调度表、普通 IPv4/IPv6 LPM 或 SR 终结逻辑。`exit` 不跳过后续 Egress/checksum/deparser 阶段。未命中目的角色的中间节点保留原路由；两端网关 default 仍 hold，错误方向/端口/模态不会获得还原机会。

控制器没有行为修改，只更新了模块说明文字；原目的表、精确规则、源调度、PRE 和路由全部保留，无需额外安装 M6 表项。

## C. 三模态统一还原

IPv4、IPv6、SR 获胜副本均使用同一还原 action：

1. 在 PolyShim 失效前读取 direction，选择主机方向的 Ethernet MAC。
2. `hdr.ipv4 = hdr.inner_ipv4`，用独立保存的 inner 替换外层/普通 IPv4 实例；赋值同时复制 header validity。
3. `hdr.ipv4.hdrChecksum=0`，随后由原有 checksum control 计算。
4. 将 inner_ipv4 实例、IPv6、SR 栈全部9项、PolyShim、ARP/TCP 实例置无效。
5. 设置 EtherType=0x0800，保留已有效的 UDP 和 protected_data。
6. 保证 scheduled=0、mcast_grp=0、egress_spec=1，退出 Ingress。

IPv4 外层被替换为恢复后的 inner，不会同时输出两份 IPv4；IPv6 和 SR 外层完全失效。M4 Egress 仅处理 scheduled=1 的副本，因此不会给还原包重新套外层。

有效 header 集合最终严格为：

```text
Ethernet / IPv4 / UDP / protected_data(16 bytes)
```

原 Deparser 顺序无需改动，无效 header 不序列化。正常实验报文 IPv4 totalLen=44、UDP length=24；Ethernet 不含 FCS 时有效报文58字节，真实 Ethernet 最小帧填充允许到60字节。

## D. 地址、MAC、TTL 与 checksum

| direction | 输出网关/端口 | Ethernet 源 MAC | Ethernet 目的 MAC |
| --- | --- | --- | --- |
| 0，h1→h2 | S2 / 1 | 08:00:00:00:02:00 | 08:00:00:00:02:02 |
| 1，h2→h1 | S1 / 1 | 08:00:00:00:01:00 | 08:00:00:00:01:01 |

发往主机的帧使用当前目的网关作为 Ethernet 源，与该主机已有的网关 ARP MAC 一致；不沿用最后一个中间交换机或 SR 广播 MAC。

inner IPv4 整体复制，srcAddr/dstAddr、diffserv、identification、flags、TTL 等保留，不执行普通路由的 TTL 递减。UDP 源/目的端口、长度、checksum 和16字节 protected_data 均原样保留。UDP checksum 的伪首部和内容没有被还原过程改变，无需重算。

原 `MyComputeChecksum` 在 Egress 后对有效 hdr.ipv4 调用 `HashAlgorithm.csum16`，重算 IPv4 header checksum；checksum control 本身未改。测试包含非默认 IPv4 字段、非零 UDP checksum、二进制 protected_data，以及故意置为旧值的 IPv4 checksum，验证最终 checksum 正确且其余字段不变。

## E. M5 不变性与一次输出

没有修改 M5 的 sequence、232 bit source/observed CRC、seen_modes、candidate_counts、decided、decision_status、winner 或 good/bad/no_majority 分支。没有新增裁决 register 或在 Python 选择副本。

本轮实际比较 M5 基线与 M6 编译 JSON：

- `adjudicate_polymorphic` 的139条 primitive 完全一致，仅忽略 source_info 行号。
- `prepare_polymorphic`、`start_polymorphic` 编译指令不变。
- register_arrays、counter_arrays、Parser、Deparser、checksum、CRC calculation 编译语义不变。
- P4Info 中五张既有表、两个公开 action、三个 counter 与 M5 基线完全一致。
- 源码检查验证 M1–M4 Parser/封装/普通转发、M5 原子事务和控制器 AST 行为不变。

M5 在原子事务内只对第一次形成多数的当前副本置 accept=1，并持久化终局状态。M6 直接使用该标记：第三个迟到模态即使 good，也没有第二次输出机会；同模态重复不计第二票、不重复记 counter。

一次输出保证沿用 M5 的32位序号、1024窗口和有限 epoch 假设；未扩大为跨重启或跨完整序号空间的永久去重承诺。

## F. 修改文件与关键位置

| 文件/位置 | 修改 |
| --- | --- |
| `polymorphic.p4:552` | 透明还原 action、全部外层失效、MAC、端口1及 exit |
| `polymorphic.p4:724` | 精确目的命中后以 accept 为唯一还原门控 |
| `polymorphic.p4:909` | 原 checksum control，未改，复用以重算恢复后的 IPv4 |
| `polymorphic.p4:933` | 原 Deparser，未改，依靠 validity 输出普通 IPv4 |
| `mycontroller.py:4` | 仅说明 M6 已接入，无控制器行为变更 |
| `class3/state-design.txt:98` | 更新 M6 hook 处理和真实证据范围 |
| `tests/check_m5.py:96` | 仅将阶段性“所有副本 hold”输出断言更新为“胜出还原、其余 hold” |
| `tests/check_m6.py` | 13组编译 JSON 离线回归及检查器正反例 |
| `tests/check_m6_pcaps.py` | 读取真实捕获文件的 M6 无故障完整路径/出口/内容/统计检查器 |
| `evidence/m6/` | 分阶段编译、回归、接口、语义不变核对及 socket 限制日志 |
| `evidence/m5-runtime/` | 本轮归档的用户 M5 真实前置材料 |

官方收发脚本、read/evaluate counters、run-poly-tests、验收预期、项目及全局 utils、拓扑、材料和参考文件均未改。M2/M3/M4 测试文件也未修改。

## G. 实际编译与离线验证

每个子步骤实际编译并复测 M2–M5：

| 阶段 | make build | M2 | M3 | M4 | M5 |
| --- | --- | --- | --- | --- | --- |
| M5 基线 | 退出0 | — | — | — | — |
| header 还原 action，尚未接入 | 退出0 | 34通过 | 9通过 | 8通过 | 15通过 |
| accept 门控、MAC及主机出口接入 | 退出0 | 34通过 | 9通过 | 8通过 | 15通过 |
| 完整检查版本 | 退出0 | 34通过 | 9通过 | 8通过 | 15通过 |

M6 新增 `python3 tests/check_m6.py`：**13组通过**，包含：

- 双向所有6种模态到达顺序，IPv4/IPv6/SR 都能成为获胜副本。
- AAA、AAB、ABB、ABC、两份一致缺第三份。
- 决定前后重复、内容不同的重复、迟到 good/bad，不产生第二份输出。
- 原始 IPv4 字段、UDP 端口与非零 checksum、16字节二进制内容保持，IPv4 checksum 修复。
- 完整9项 SR 栈清除，连续两个序号的源调度/三路径/目的还原。
- 用户真实 M5 输入的离线重放，正向3份、反向1份正确还原到模型出口。
- pcap 检查器拒绝重复/缺失输出、外层泄漏、错误 checksum/数据/端口/MAC、入口 sequence 不同、缺失中间路径和错误 counter。
- 多序号映射及相同数据无法唯一关联时明确拒绝判定。

上述执行解释 p4c 生成的 JSON，extern/PRE/checksum 为 Python 模型。错误数据是离线夹具，没有安装真实故障表项。临时合成 pcap 仅测试检查器且不归档为运行证据；**真实 M5 抓包输入的离线重放仍不是 M6 原生 BMv2 执行。**

Python 静态检查及 `git diff --check` 实际通过。可复现命令：

```bash
source ~/p4setup.bash
make build
python3 -m py_compile mycontroller.py tests/check_m5.py tests/check_m6.py tests/check_m6_pcaps.py receive-poly.py run-poly-tests.py
python3 tests/check_m2_parser.py
python3 tests/check_m3.py
python3 tests/check_m4.py
python3 tests/check_m5.py
python3 tests/check_m6.py
git --git-dir=.course-git --work-tree=. diff --check
```

完整日志见 `evidence/m6/`。初始未接入的还原 action 有 unused 警告，接入后消失；最终保留基线五个 ARP 常量 unused 警告，以及导入 Makefile 时间在未来导致的 clock skew 提示。日志记录 p4c 实际执行且退出0，没有编译失败。未改系统时间或工具链。

工具仍为 p4c 1.2.5.15 / BMv2 1.15.4-883d4eae / Mininet 2.3.1b4。

## H. 普通 Ubuntu 真实验证命令（待执行）

先保存并退出旧拓扑；以下使用**新的拓扑和流水线**，将序号、窗口和 counter 从零开始，不延用 M5 good=3/1 的状态。使用空的 `evidence/m6-runtime/` 目录，保存本次版本、输出和真实 pcap。无需配置 GitHub remote。

终端 A：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
mkdir -p evidence/m6-runtime
set -o pipefail
git --git-dir=.course-git --work-tree=. rev-parse HEAD > evidence/m6-runtime/revision.txt
make build 2>&1 | tee evidence/m6-runtime/build.log
make 2>&1 | tee evidence/m6-runtime/mininet.log
```

终端 B，待十台交换机启动：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
set -o pipefail
python3 mycontroller.py 2>&1 | tee evidence/m6-runtime/controller.log
```

确认控制器成功退出、规则安装无错误后，在终端 A 的 Mininet 提示符执行下列命令；不要输入 `mininet>` 字样。

先执行普通协议回归：

```text
h1 ip -4 neigh flush dev eth0
h2 ip -4 neigh flush dev eth0
pingall
h1 ping6 -c 2 fe80::5678%eth0
h2 ping6 -c 2 fe80::1234%eth0
h1 sh -c 'timeout 60 python3 -u receive.py > /tmp/m6-h1-ordinary.log 2>&1 &'
h2 sh -c 'timeout 60 python3 -u receive.py > /tmp/m6-h2-ordinary.log 2>&1 &'
sh sleep 1
h1 sh -c "printf '4 2 2 1\nq\n' | python3 send-sr.py 10.0.2.2"
h2 sh -c "printf '4 1 1 1\nq\n' | python3 send-sr.py 10.0.1.1"
sh sleep 1
h1 cat /tmp/m6-h1-ordinary.log
h2 cat /tmp/m6-h2-ordinary.log
```

清理仅限 IPv4 邻居，不删除拓扑已有的 IPv6 静态邻居。SR 通过必须在对端接收日志中看到相应 UDP/4321，不能把发送端打印当成到达证据。

正向一次输入、反向一次输入，依次开启接收器，避免接收器把本机发送的另一个方向原包也计入：

```text
h2 sh -c 'python3 -u receive-poly.py --timeout 10 --expect 1 > /tmp/m6-h2-poly.log 2>&1 &'
sh sleep 1
h1 python3 send-poly.py 10.0.2.2 m6-forward
sh sleep 11
h2 cat /tmp/m6-h2-poly.log
h1 sh -c 'python3 -u receive-poly.py --timeout 10 --expect 1 > /tmp/m6-h1-poly.log 2>&1 &'
sh sleep 1
h2 python3 send-poly.py 10.0.1.1 m6-reverse
sh sleep 11
h1 cat /tmp/m6-h1-poly.log
```

预期每次发送只有一条 POLY_SEND，对端仅一条 POLY_RECV，protected_hex 与对应发送输出完全一致，summary 为 received=1 expected=1。**接收脚本到达期望数量后会提前停止 sniff，单凭 summary 不能证明没有第二份迟到输出。** 还必须执行后面的真实出口 pcap 检查。

拓扑保持运行，终端 C 读取 counter 和终局状态：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
set -o pipefail
python3 read-counters.py 2>&1 | tee evidence/m6-runtime/counters.log
python3 evaluate-counters.py evidence/m6-runtime/counters.log | tee evidence/m6-runtime/feedback.log
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\nregister_read MyIngress.seq_tag 1\nregister_read MyIngress.seen_modes 1\nregister_read MyIngress.decided 1\nregister_read MyIngress.decision_status 1\nregister_read MyIngress.decided_crc 1\n' | simple_switch_CLI --thrift-port 9090 | tee evidence/m6-runtime/s1-state.log
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\nregister_read MyIngress.seq_tag 1\nregister_read MyIngress.seen_modes 1\nregister_read MyIngress.decided 1\nregister_read MyIngress.decision_status 1\nregister_read MyIngress.decided_crc 1\n' | simple_switch_CLI --thrift-port 9091 | tee evidence/m6-runtime/s2-state.log
```

默认 Thrift 端口 S1=9090、S2=9091；若启动日志显示不同，以日志为准。新流水线下两端预期均是各模态 good=1、bad=0、no_majority=0；两端 slot1 的 seq_tag=1、seen=7、decided=1、status=1。CRC 应与各方向真实 pcap 的值一致，随机 UDP 源端口使其可以不同于历史 M5 数值。

终端 A 执行 `exit` 正常关闭拓扑以刷新 pcap。**在归档前不要 make clean。** 终端 C：

```bash
cp pcaps/*.pcap evidence/m6-runtime/
cp /tmp/m6-h1-poly.log /tmp/m6-h2-poly.log /tmp/m6-h1-ordinary.log /tmp/m6-h2-ordinary.log evidence/m6-runtime/
python3 tests/check_m6_pcaps.py --pcap-dir evidence/m6-runtime --direction 0 --expect 1 --counters evidence/m6-runtime/counters.log 2>&1 | tee evidence/m6-runtime/check-forward.log
python3 tests/check_m6_pcaps.py --pcap-dir evidence/m6-runtime --direction 1 --expect 1 --counters evidence/m6-runtime/counters.log 2>&1 | tee evidence/m6-runtime/check-reverse.log
```

实际执行后应得到两条 M6_PCAP_OK，**目前未取得这些输出**。检查器逐项验证：

1. 源主机口仅一份该方向原始 IPv4/UDP 输入，源网关三个出口是同一 sequence/CRC/inner。
2. s11/s12、s21/s22、s31/s32 全部逐跳抓包及目的网关三个入口具有同一 sequence，TTL/hopLimit/SR剩余栈正确。
3. 目的主机出口存在且只有一份正确普通 IPv4；没有 IPv4/IPv6/SR 外层或 PolyShim 泄漏。
4. 主机 MAC、网关 MAC、IPv4 checksum 正确，整份 inner（除可重算的 IPv4 checksum）与源输入逐字节一致，包含 UDP 端口/checksum及全部16字节 protected_data。
5. 官方 counter 日志的该方向网关 good/bad/no_majority 精确符合新流水线一次输入的预期。

获胜输出没有 sequence 字段，检查器通过“入口 sequence↔完整 inner↔出口完整 inner”建立唯一对应，不往 UDP/payload 加序号。对多份完全相同的原始 datagram，无法仅凭还原出口区分其序号归属，检查器会拒绝作出逐序号一次输出结论；多包测试应使用不同 message 或 UDP 源端口。

旧 M4 full 检查器有“目的主机不得出现还原输出”的阶段断言，保持原样；M6 真实验收应使用新增 M6 检查器，不放宽旧工具，也不能拿旧 M5 pcaps代替新版本抓包。

## I. 未完成的真实测试与边界

- M6 正反向真实收发、出口去重、三模态获胜顺序变化的原生验证待普通终端执行；本轮只有编译与离线覆盖。
- 单模态篡改、丢包、三份各异、真实重复/迟到及并发压力尚未原生验证；未实现故障表/action或 `--fault`，不声称实验三五场景通过。
- 官方 `receive-poly.py` 和 `run-poly-tests.py` 未改，未放宽数量或 counter 要求；不凭接收器提前停止后的 summary 断言没有重复。
- 普通 IPv6 反向及 SR 双向真实回归仍需补充本次终端日志。
- 沿用 M5 有限窗口、半序空间和重启约束；未增加超时、epoch协商、密码学认证或持久化。

沙箱实际错误及未运行状态见 `evidence/m6/runtime-status.log`。没有修改 AppArmor、全局 tutorials/utils、Ubuntu或 P4/BMv2/Mininet 工具链，没有使用沙箱绕过参数。

## J. Git 记录

继续使用 `git --git-dir=.course-git --work-tree=.`，保留 M1–M5 历史：

- `a76b167`：归档用户提供的 M5 真实无故障证据及原工具复查。
- `526e5dd81501882b8305b1b3518d7f344c835f41`：M6 实现、状态说明、离线回归、pcap检查器和实际编译/静态证据。
- 本报告另作提交，以避免递归引用自身哈希。

进入本轮时已有的未跟踪空文件 `gRPC`、`h1`、`h2`、`pingall` 保留原样，未纳入提交；没有配置 remote、重写历史或创建标签。

本轮 M6 完成后停止，等待下一步验收指令。
