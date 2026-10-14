# 实验二 M4 开发报告

M4 代码、分步编译和离线检查已完成；**尚未通过实验二运行验收**。
未实现 M5/M6、故障注入、统计计数器或五场景自动验收；没有创建 `class2-multicast` 标签。

## A. 本轮修改概述

先阅读并核对 `STUDENT_TODO.md`、当前 P4/控制器、拓扑、M3 报告、实验二官方指导及 experiment2 参考接口。
在现有工程上扩展 Egress，按 PRE 已决定的出口生成三种外层；增加 P4Runtime 可配置的目的网关临时丢弃接口。

M3 的 `polymorphic_schedule`、`start_polymorphic`、`sequence_register`、入口资格检查、232 bit CRC 输入、hash 参数、group 10 和两个网关的 replica 参数未改。
原有 18 条 ARP/IPv4/IPv6 路由调用、Parser、普通转发 action/table、checksum control 和 Deparser 未重写。

本轮把用户提供的 M3 真实运行结果与六份原始 pcap 保存到 `evidence/m3-runtime/`，并用原工具复查通过；来源和结论范围独立记录，未混入 M4 离线结果。

## B. IPv4 封装设计

只对 `meta.scheduled==1`、BMv2 PRE instance type=5、内层与 PolyShim 有效、direction 为 0/1 的副本处理。
普通报文不进入封装分支。非法出口或不完整的暂存副本直接丢弃。

端口 2 输出：

```text
Ethernet / outer IPv4 / PolyShim(mode=1) / inner IPv4 / UDP / protected_data
```

外层所有字段显式初始化：version=4、IHL=5、diffserv=0、totalLen=78、identification=0、flags=0、fragment offset=0、TTL=64、protocol=253。
checksum 初置 0，由现有 `MyComputeChecksum` 在 Egress 之后重新计算；中间交换机递减外层 TTL 后继续重算。

| direction | 外层 IPv4 地址 | 源网关 source MAC | 第一跳 destination MAC |
| ---: | --- | --- | --- |
| 0 | 10.0.1.1 → 10.0.2.2 | 08:00:00:00:01:00 | 08:00:00:00:11:00 |
| 1 | 10.0.2.2 → 10.0.1.1 | 08:00:00:00:02:00 | 08:00:00:00:12:00 |

第一跳 MAC 与原控制器 IPv4 转发表参数一致，后续沿原 s11/s12 LPM 路径转发。
`hdr.inner_ipv4` 独立保存并保持原字节，外层初始化和 TTL 更新只作用于 `hdr.ipv4`。

## C. IPv6 封装设计

端口 3 输出：

```text
Ethernet / outer IPv6 / PolyShim(mode=2) / inner IPv4 / UDP / protected_data
```

EtherType=0x86dd、version=6、trafficClass=0、flowLabel=0、payLoadLen=58、nextHdr=253、hopLimit=64；所有 IPv6 字段初始化。
正向地址 `fe80::1234 → fe80::5678`，反向交换。
源/下一跳 MAC 采用上表中同方向参数，与现有 IPv6 静态路由一致；没有更改 IPv6 LPM 规则。
外层沿 s21/s22 路径转发，内层 IPv4/UDP/data 不变。

## D. SR 封装设计

端口 4 输出：

```text
Ethernet(type=0x1234) / SR stack / PolyShim(mode=3) / inner IPv4 / UDP / data
```

源网关出口已经由 PRE 选为 4，因此 SR 栈不再包含源网关的端口 4：

| direction | 源 Egress 栈端口，按发出顺序 | BOS | 第一台中间节点 | 第二台中间节点 |
| ---: | --- | --- | --- | --- |
| 0 | 2、2、1 | 0、0、1 | S31 弹出 2 | S32 弹出 2 |
| 1 | 1、1、1 | 0、0、1 | S32 弹出 1 | S31 弹出 1 |

只使 `srcRoutes[0..2]` 有效，逐项初始化 bos/port；封装前将整个九项外层栈与旧 IPv4/IPv6 实例置无效，避免输出多余元素。
SR 使用与原发送脚本相同的广播目的 MAC；转发依据为栈端口，源 MAC 为源网关 MAC。

原 `srcRoute_nhop()` 读取栈首端口后 `pop_front(1)`，因此目的网关收到的栈只剩 `[1,bos=1]`。
目的网关拦截在 `srcRoute_finish()` 之前，避免把栈后的 PolyShim 误标为普通 IPv4。
普通 SR 不带 PolyShim，继续原弹栈和终止路径。

## E. 双向路径说明

| 方向 | 模态 | 真实物理路径与端口 |
| --- | --- | --- |
| 正向 | IPv4 | S1:p2 → S11:p1入/p2出 → S12:p1入/p2出 → S2:p2入 |
| 正向 | IPv6 | S1:p3 → S21:p1入/p2出 → S22:p1入/p2出 → S2:p3入 |
| 正向 | SR | S1:p4 → S31:p1入/p2出 → S32:p1入/p2出 → S2:p4入 |
| 反向 | IPv4 | S2:p2 → S12:p2入/p1出 → S11:p2入/p1出 → S1:p2入 |
| 反向 | IPv6 | S2:p3 → S22:p2入/p1出 → S21:p2入/p1出 → S1:p3入 |
| 反向 | SR | S2:p4 → S32:p2入/p1出 → S31:p2入/p1出 → S1:p4入 |

IPv4 TTL / IPv6 hopLimit 在源出口为 64、第一台中间节点出口为 63、第二台中间节点出口及目的网关入口为 62。
SR 栈在对应位置为 3、2、1 项。
Egress 没有重新选择出口，没有根据 egress_rid、随机数或 modality_id 决定出口，也没有重新分配序号或计算源 CRC。

## F. 目的网关临时拦截

新增 `MyIngress.polymorphic_destination`，exact key 为 ingress_port（9 bit）、PolyShim direction（8 bit）、modality_id（8 bit）。
`hold_polymorphic()` 执行 `mark_to_drop()` 后立即退出 Ingress，不做投票或还原。
该表只在已通过完整性检查的 PolyShim 分支中调用，普通 IPv4/IPv6/ARP/SR 不进入。

控制器在原路由之后、启动 PRE/源调度之前配置：

| 网关 | direction | (ingress_port, modality_id) | action |
| --- | ---: | --- | --- |
| S2 | 0 | (2,1)、(3,2)、(4,3) | hold_polymorphic |
| S1 | 1 | (2,1)、(3,2)、(4,3) | hold_polymorphic |

还仅对 S1/S2 将本表 default action 改为 hold，防止某条精确规则缺失或异常方向/入口导致泄漏。
中间交换机保持 default NoAction，没有目的网关表项；反向中间出口 1 继续正常工作。
此外，SR/PolyShim 若在未配置目的角色的节点提前到达终止栈，直接丢弃，绝不调用普通 SR 的 EtherType 改写。

首次逐跳离线测试发现，将所有节点的出口 1 当成主机口会阻断反向中间路径；已改为上述控制面配置的网关默认动作，保留相应回归。
该配置接口为 M5 预留：后续可将精确命中的 hold 替换为数据面裁决入口，未命中仍保持 drop。

## G. 修改文件与代码位置

| 文件 | 关键位置 / 用途 |
| --- | --- |
| polymorphic.p4:16 | BMv2 PRE instance type 常量 |
| polymorphic.p4:362 | hold_polymorphic action |
| polymorphic.p4:367 | 目的网关表与可配置默认动作 |
| polymorphic.p4:502 | PolyShim 检查后、普通路由前应用目的表 |
| polymorphic.p4:536 | 封装 SR 的终止保护 |
| polymorphic.p4:565 | Egress 封装、外层有效性清理及出口检查 |
| polymorphic.p4:582 | IPv4 封装 |
| polymorphic.p4:600 | IPv6 封装 |
| polymorphic.p4:614 | SR 封装 |
| mycontroller.py:56 | 目的网关精确表项 helper |
| mycontroller.py:225 | 两个网关的默认 drop 和六条到达规则 |
| tests/check_m3.py | 解释器适配新表 hit/miss；验证新增 INSERT/MODIFY 请求，仍核对原 PRE/路由/调度参数 |
| tests/check_m4.py | 编译 JSON、真实控制器 protobuf、checksum 模型及逐跳离线回归 |
| tests/check_m4_pcaps.py | 读取实际抓包，核对源输入、三出口、所有中间入/出口和目的端禁止输出 |
| evidence/m3-runtime/ | 用户提供的真实 M3 抓包、结果说明、复查日志及 SHA256 |
| evidence/m4/ | 本轮实际编译与离线检查记录 |

没有修改全局 tutorials/utils、本地 utils、拓扑、实验三验收脚本或测试预期；没有升级工具链。

## H. 编译结果

| 步骤 | 命令 | 实际结果 |
| --- | --- | --- |
| M3 起点 | make build | 退出码 0 |
| IPv4 封装 | make build | 退出码 0 |
| IPv6 封装 | make build | 退出码 0 |
| SR 封装 | make build | 退出码 0 |
| 临时目的拦截 | make build | 退出码 0 |
| 修正反向端口/网关角色边界 | make build | 退出码 0 |

完整输出在 `evidence/m4/build-00…05-*.log`。没有编译 error 或新增 unsupported warning；保留原五项 unused ARP 常量与 Make 时间戳提示。
P4Info 的原调度接口保持一致，新增目的表和 action 已通过实际 protobuf 构造核对，见 `p4info-contract.txt`。

实际 Python 静态检查和 Git 空白检查通过：

```bash
python3 -m py_compile mycontroller.py tests/check_m3.py tests/check_m4.py tests/check_m4_pcaps.py
git --git-dir=.course-git --work-tree=. diff --check
```

工具版本保持 p4c 1.2.5.15、BMv2 1.15.4-883d4eae、Mininet 2.3.1b4。源码及编译产物 SHA256 见 `verification.txt`。

## I. 离线测试结果

- M4：**8 组测试通过**，包含双向三封装、长度、checksum、BOS/栈顺序、header validity、内层字节保持、sequence/CRC、原普通转发和 ARP、非法出口、非 PRE instance、不完整头、六条逐跳路径、网关拦截及精确规则缺失后的默认 drop。
- M3：**9 组回归通过**，原序号、CRC、PRE、方向和原路由断言保留；只为新表的 hit/miss 与默认动作请求作适配。
- M2：**34 个 Parser 用例通过**。
- 抓包工具用临时的、明确标注为合成的 pcap 验证过正确路径、缺失中间捕获、错误 checksum 和主机口泄漏的判定；这些临时文件未作为项目运行证据保存。

这里使用的是 **Python 对 p4c JSON 的解释、checksum/PRE 模型和合成逐跳输入**，不是实际 BMv2 执行。
首次发现反向出口 1 问题的失败日志保留在 `offline-tests-initial.log`，修正后的日志为 `offline-tests.log`。

## J. 真实运行结果与待执行命令

### 已有的 M3 真实证据

用户报告正常 Ubuntu 终端中 make build 成功、10 台交换机启动、pingall 为 0% dropped；这些三项没有完整终端原始日志，按“用户报告”记录。
本轮读取用户提供的六份源出口原始 pcap 后，实际复查为：

| 方向 | 每个出口份数 | 总份数 | sequence | source_crc32 |
| ---: | ---: | ---: | ---: | --- |
| 0 | 1 | 3 | 1 | 0xee6384ce |
| 1 | 1 | 3 | 1 | 0xc20d78ca |

见 `evidence/m3-runtime/README.md` 和两个 `pcap-recheck-*.log`。这只证明 M3 源网关复制，不能作为 M4 路径通过的证据。

### 当前 M4 状态

沙箱实际探测仍无法创建 AF_INET socket；本轮没有启动 BMv2 或 Mininet，没有改系统安全策略。
**尚未通过实验二运行验收**，没有创建完成标签。

### 普通 Ubuntu 终端完整验证步骤

先结束旧的本项目拓扑，使用新启动的交换机和流水线。以下命令尚未在本轮执行，所有“预期”均是待验证条件。

终端 A：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
mkdir -p evidence/m4-runtime
set -o pipefail
make build 2>&1 | tee evidence/m4-runtime/build.log
make
```

终端 B：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
set -o pipefail
python3 mycontroller.py 2>&1 | tee evidence/m4-runtime/controller.log
```

确认控制器无异常后，在终端 A 的 Mininet 提示符依次执行，不包含 `mininet>` 前缀：

```text
h1 ip neigh flush dev eth0
h2 ip neigh flush dev eth0
pingall
h1 ping6 -c 2 fe80::5678%eth0
h2 ping6 -c 2 fe80::1234%eth0
h1 sh -c 'timeout 60 python3 -u receive.py > /tmp/m4-h1-ordinary.log 2>&1 &'
h2 sh -c 'timeout 60 python3 -u receive.py > /tmp/m4-h2-ordinary.log 2>&1 &'
h1 sh -c "printf '4 2 2 1\nq\n' | python3 send-sr.py 10.0.2.2"
h2 sh -c "printf '4 1 1 1\nq\n' | python3 send-sr.py 10.0.1.1"
sh sleep 1
h1 cat /tmp/m4-h1-ordinary.log
h2 cat /tmp/m4-h2-ordinary.log
h1 python3 send-poly.py 10.0.2.2 m4-forward
h2 python3 send-poly.py 10.0.1.1 m4-reverse
sh sleep 2
```

每次 `send-poly.py` 应只有一条 POLY_SEND，记录命令和实际输出。两方向各发一次即可；不要从主机发送三种模态来代替 PRE。
新报文使用随机 UDP source port，因此实际 CRC 可以与历史 M3 的数值不同；同一原包的三份必须一致。
普通 ping/IPv6/SR 应继续工作；受保护流量此时不应送到目的主机。

保持拓扑运行，在终端 C 读取临时目的规则和序号：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\n' | simple_switch_CLI --thrift-port 9090 | tee evidence/m4-runtime/s1-state.log
printf 'table_dump MyIngress.polymorphic_destination\nregister_read MyIngress.sequence_register\n' | simple_switch_CLI --thrift-port 9091 | tee evidence/m4-runtime/s2-state.log
```

预期 S1 的 direction=1、S2 的 direction=0 各有三条精确 hold 规则，两个网关默认动作也是 hold；全新输入下序号分别为 `[1,0]` 和 `[0,1]`。
随后在终端 A 执行 `exit`，关闭拓扑并刷新 pcap；不要先执行 make clean。

终端 C 检查源输入/三个出口，再检查所有物理跳与目的端：

```bash
set -o pipefail
python3 tests/check_m4_pcaps.py --direction 0 --scope source --expect 1 2>&1 | tee evidence/m4-runtime/source-forward.log
python3 tests/check_m4_pcaps.py --direction 1 --scope source --expect 1 2>&1 | tee evidence/m4-runtime/source-reverse.log
python3 tests/check_m4_pcaps.py --direction 0 --scope full --expect 1 2>&1 | tee evidence/m4-runtime/path-forward.log
python3 tests/check_m4_pcaps.py --direction 1 --scope full --expect 1 2>&1 | tee evidence/m4-runtime/path-reverse.log
```

`source` 检查源网关 p1 入、p2/p3/p4 出：源主机只有一份，三个出口使用各自外层，序号/CRC/内层与源包对应。
`full` 对 E 节每条路径检查源出、中间节点一入一出、目的网关入，合计每个方向 18 个模态捕获点；核对 TTL、栈变化、地址、checksum、序号和内容。
它还检查目的网关 p1 出口中既没有封装副本，也没有提前还原的本次 IPv4/UDP/5000 报文。
任何缺文件、少包、多包、错误物理路径或内容差异都会失败。

人工查看 S1/S2 三个出口及目的入口：

```bash
for m4_sw in s1 s2; do
    for m4_port in 2 3 4; do
        tcpdump -nn -e -xx -r "pcaps/${m4_sw}-eth${m4_port}_out.pcap"
        tcpdump -nn -e -xx -r "pcaps/${m4_sw}-eth${m4_port}_in.pcap"
    done
done
```

查看 s11/s12、s21/s22、s31/s32 的双向逐跳捕获：

```bash
for m4_sw in s11 s12 s21 s22 s31 s32; do
    for m4_port in 1 2; do
        tcpdump -nn -e -xx -r "pcaps/${m4_sw}-eth${m4_port}_in.pcap"
        tcpdump -nn -e -xx -r "pcaps/${m4_sw}-eth${m4_port}_out.pcap"
    done
done
tcpdump -nn -e -xx -r pcaps/s1-eth1_out.pcap
tcpdump -nn -e -xx -r pcaps/s2-eth1_out.pcap
```

最后保存真实抓包、收发/回归记录及对应 Git 版本，再清理：

```bash
cp pcaps/*.pcap evidence/m4-runtime/
git --git-dir=.course-git --work-tree=. rev-parse HEAD > evidence/m4-runtime/git-commit.txt
make stop
make clean
```

后续可在归档目录复查，例如：

```bash
python3 tests/check_m4_pcaps.py --pcap-dir evidence/m4-runtime --direction 0 --expect 1
python3 tests/check_m4_pcaps.py --pcap-dir evidence/m4-runtime --direction 1 --expect 1
```

只有实际运行完成、两方向完整路径检查通过、普通功能回归正常并保存真实证据后，才允许创建 `class2-multicast`；本轮不提供或执行提前打标签命令。

## K. 未解决的问题

1. M4 的真实三路径、原普通功能回归及目的主机隔离仍待上述正常终端验证。合成轨迹或 M3 旧 pcap 不能替代。
2. 当前仅支持课程固定 IPv4/UDP/16 字节数据、固定地址与端口拓扑；封装长度据此固定。
3. 目的网关故意丢弃所有封装副本，没有多数、去重、窗口、统计或还原。这是 M4 的暂时行为，不是最终接收成功。
4. 网关角色默认动作需要控制器成功安装；若完全未安装配置，不能依赖端口号推断角色。缺少单条精确规则时，已配置的网关默认 hold 会兜底。
5. BMv2 的 PRE instance type=5 已核对本机目标实现；迁移其他架构需要重新核对，当前没有更换目标或工具版本。

## L. M5 开发建议

保留源调度和 Egress，先在现有精确目的规则命中处接入 P4 数据面的裁决路径，未匹配默认继续 drop。
按 direction 与 sequence 管理有限窗口、seq_tag、候选 CRC、seen bitmap 和 decided，不能把同一模态重复包当第二票。
对当前实际内层字段按原 232 bit 顺序重算 observed_crc，不能直接比较 source_crc32。
首次副本先丢弃，仅让当前形成多数的副本进入之后 M6 的还原路径；迟到副本不再次输出。
先完成真实 M4 验收，再开展裁决和故障场景；本轮没有预先加入相关 register、counter 或 Python 投票。

## M. Git commit

- M3 真实证据归档及原始 pcap：`b1644c5`。
- M4 实现、测试与实际构建记录：**`987429b`**。
- 本报告随后单独提交。历史 M3 实现 `d7284f6`、报告 `4f886aa` 均保留。

```bash
git --git-dir=.course-git --work-tree=. show --stat 987429b
git --git-dir=.course-git --work-tree=. log --oneline -5
git --git-dir=.course-git --work-tree=. tag --list class2-multicast
```

本轮到此停止，等待后续指令。
