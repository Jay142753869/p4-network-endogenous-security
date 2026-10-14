# 实验三最终阶段：故障注入与五场景验收准备

已完成真实 P4 数据面故障注入、P4Runtime 控制器接口、分步编译、M2–M6 离线回归和故障检查器。**本轮没有通过真实 BMv2 五场景验收的结果。** 实际 AF_INET socket 创建仍被沙箱拒绝；没有启动本轮 Mininet，没有伪造 SCENARIO_PASS 或 ALL_SCENARIOS_PASS。

官方 `run-poly-tests.py` 保持原样，场景、接收数量、counter token 和成功判定均未修改。普通 Ubuntu 终端的最终验收命令和原始 pcap 核查方法见下文。

## A. 阅读依据与真实前置证据

核对了当前 `polymorphic.p4`、`mycontroller.py`、M5/M6 报告、`class3/state-design.txt`、官方第三次实验指导、第三次实验参考状态声明和模型，以及官方收发、counter 和五场景工具。

故障选在中间节点已完成 Parser/结构校验之后，普通路径处理之前：源网关已经计算 source_crc32，目的网关尚未计算 observed_crc。没有在发送主机修改数据，没有在 Python 执行最终裁决。

用户新增的 M6 真实材料已经归档到 `evidence/m6-runtime/`（52份原始pcap及counter日志）。本轮使用**未修改**的 `tests/check_m6_pcaps.py` 实际复查：

| 方向 | 原始输入/主机出口 | sequence | source_crc32 |
| --- | --- | ---: | --- |
| h1→h2 | 1 / 1，per_sequence=1 | 1 | 0x93d25cf1 |
| h2→h1 | 1 / 1，per_sequence=1 | 1 | 0x48f21ff4 |

两端各模态 good=1、bad=0、no_majority=0。用户同时报告 M6 接收 summary 和普通 IPv4/IPv6 双向真实通信通过；对应终端接收/普通协议日志没有包含在新增目录中，本轮没有亲自运行这些命令。普通 SR 双向仍缺明确真实回归记录。

已有 M5 真实无故障证据仍保留在 `evidence/m5-runtime/`。M5/M6 旧运行证据不能冒充本轮故障五场景结果；历史开发报告保留当时状态，本报告记录后续进展。

## B. P4 故障接口与处理流程

新增表 `MyIngress.polymorphic_fault`，size=1024，所有字段 exact：

| 匹配字段 | 位宽 |
| --- | ---: |
| standard_metadata.ingress_port | 9 |
| hdr.poly.direction | 8 |
| hdr.poly.modality_id | 8 |
| hdr.poly.sequence_number | 32 |

不使用 slot 或低10位代替完整 sequence。默认 action 为 const NoAction。

新增 action：

```p4
action fault_corrupt(bit<128> xor_mask) {
    hdr.protected_data.value = hdr.protected_data.value ^ xor_mask;
}
action fault_drop() {
    mark_to_drop(standard_metadata);
    exit;
}
```

只在完整合法 PolyShim 分支调用故障表，顺序为：

```text
Parser → parser_error/完整性/模态校验 → polymorphic_fault
       → 目的角色表（仅目的网关计算observed_crc及投票）
       → 首次多数才透明还原，否则丢弃
中间节点未命中目的角色时继续原普通IPv4/IPv6/SR转发。
```

corrupt action 的编译结果只有一次 protected_data 赋值；不改 source_crc32、inner IPv4、UDP 或任何裁决状态。后续普通转发仍按原设计更新外层 MAC/TTL/hopLimit/checksum，这与故障 action 的字段修改范围不同。故障后的 UDP checksum 刻意不重算，完整真实数据进入原 M5 observed CRC 检测；官方单故障场景由未损坏的两份副本输出原文。

drop 使用 exit，不能再被后续普通路由覆盖 drop 状态，也不进入目的 counter/投票。未到达的模态不会因缺失被记 bad。

## C. 控制器参数、重复和错误处理

支持以下原有官方语法，并支持重复传入多个 `--fault`：

```bash
python3 mycontroller.py --fault corrupt:1:1:0x1
python3 mycontroller.py --fault drop:2:1
python3 mycontroller.py --fault corrupt:1:1:0x1 --fault corrupt:2:1:0x2 --fault corrupt:3:1:0x4
```

- MODE：1、2、3。
- SEQ：unsigned 32 bit，0至0xffffffff；支持回绕后的0。
- MASK：unsigned 128 bit，0至2^128-1，按 protected_data 网络位序解释。0x1 翻转16字节数据最后一字节的最低位；0 是合法的 no-op XOR。
- 数字支持无符号十进制或0x十六进制；负数、越界、缺少字段、额外字段、未知操作和非法数字在连接交换机前拒绝。
- 完全相同的重复规则去重，只安装一次，避免重复 INSERT 或人为重复 XOR。
- 相同 MODE/SEQ 的不同 MASK，或 corrupt/drop 冲突，明确报错；不暗中覆盖、不合并为新故障。

每条逻辑规则安装两个方向的精确项，接口没有新增 DIRECTION 参数。控制器先校验全部规则，安装顺序是原路由/目的角色 → 故障规则 → PRE/源调度。没有参数时不安装任何故障项。

P4Runtime RPC 写入失败现在返回非零，并通过 finally 关闭连接，避免把控制器写入失败当成成功。控制器正常返回也不构成故障发生的证明，仍需下文真实 pcap。

## D. 实际注入位置与双向路径

| MODE | 唯一注入交换机 | 正向匹配 | 反向匹配 |
| --- | --- | --- | --- |
| 1，IPv4 | s11 | ingress=1，direction=0 | ingress=2，direction=1 |
| 2，IPv6 | s21 | ingress=1，direction=0 | ingress=2，direction=1 |
| 3，SR | s31 | ingress=1，direction=0 | ingress=2，direction=1 |

正向：S1→s11/s21/s31→s12/s22/s32→S2；反向：S2→s12/s22/s32→s11/s21/s31→S1。

正向在第一台中间节点注入，反向在第二台注入。每个模态的既有无环物理路径只经过其注入节点一次，另一台中间节点、S1/S2 和预留 s41/s42 不安装故障规则。SR 的剩余端口栈不变，没有添加回送或重注入路径。

反向故障也使用相同 --fault 参数；匹配方向和入口端口，错误的方向/端口组合不命中。该设计不声称对人为构造的循环或重注入流量提供全网一次性标记。

## E. 官方五场景的 CRC、输出和 counter 预期

每个场景使用新源序号1。令该场景原始232bit输入的 CRC 为 C0，各场景 C0 可不同（send-poly.py 使用随机 UDP 源端口）。source_crc32 在所有副本上始终保留 C0。

固定29字节输入、对末16字节做 XOR 时，可离线推导：

```text
C1 = CRC(实际数据 XOR 0x1) = C0 XOR 0x77073096
C2 = CRC(实际数据 XOR 0x2) = C0 XOR 0xee0e612c
C4 = CRC(实际数据 XOR 0x4) = C0 XOR 0x076dc419
```

上述是数学预期，不是本轮实测CRC。三种差分互异且非零，因此 no-majority 的三个实际 observed CRC 必然不同。实际检查仍直接对到达字段按 M3/M5 原有232bit顺序重算，不通过 source_crc32 投票。

| 场景 | 目的观察CRC（mode1/2/3） | 主机输出 | good[1,2,3] | bad[1,2,3] | no_majority |
| --- | --- | ---: | --- | --- | ---: |
| no-fault，S2裁决 | C0/C0/C0 | 正确原文1份 | 1,1,1 | 0,0,0 | 0 |
| reverse，S1裁决 | C0/C0/C0 | 正确原文1份 | 1,1,1 | 0,0,0 | 0 |
| corrupt-mode1 | C1/C0/C0 | 正确原文1份 | 0,1,1 | 1,0,0 | 0 |
| drop-mode2 | C0/缺失/C0 | 正确原文1份 | 1,0,1 | 0,0,0 | 0 |
| no-majority | C1/C2/C4 | 0份 | 0,0,0 | 0,0,0 | 1 |

每场只发送一方向，所以另一端裁决 counter 应全部为0。未到达模态没有 good/bad 事件；首次多数和迟到补记沿用原M5逻辑，没有放宽统计条件。

## F. 不变性、编译与离线结果

实际对 M6 编译基线与最终 JSON 比较，忽略 source_info 行号后，以下原指令保持完全一致：

- M3 start/prepare、sequence/source CRC。
- M5 adjudicate（139条primitive）及全部 register/counter。
- M6 restore。
- 原 IPv4/IPv6/SR/ARP 转发 action、Parser、Deparser、checksum 和 CRC calculation。

P4Info 五张既有表、公开调度/裁决action及三个counter接口未变。新接口实际ID：fault表39334879，corrupt action25288647，drop action29997976；MASK参数128bit。原路由、角色和PRE的实际protobuf请求与无故障配置逐一比较保持一致。

每步实际执行 make build：基线、P4故障表、控制器、故障测试、完整最终检查，全部退出0；完整输出在 `evidence/final/build-00..04-*.log`。保留基线五个ARP常量unused警告、导入Makefile未来时间及clock skew提示；日志中p4c实际执行，没有编译失败。未修改系统时钟或工具链。

最终实际通过：

| 命令 | 离线结果 |
| --- | --- |
| python3 tests/check_m2_parser.py | 34项 |
| python3 tests/check_m3.py | 9组 |
| python3 tests/check_m4.py | 8组 |
| python3 tests/check_m5.py | 15组 |
| python3 tests/check_m6.py | 13组 |
| python3 tests/check_faults.py | 14组 |

新增故障检查覆盖：官方五场景对应数据流、两个方向、全部6种到达顺序；完整序号1与1025、0及0xffffffff；模式/方向/端口不匹配；MASK=0、最低/最高位、128位全1；重复/冲突规则；连续发送仅目标序号受影响；普通协议和非法PolyShim不注入；真实P4Runtime protobuf构造；RPC错误返回；原始pcap检查器的正例与未注入、重复XOR抵消、CRC掩盖、重复输出、错误丢包位置等反例。

Python语法、git diff --check及官方工具未修改检查通过。工具仍为p4c 1.2.5.15、BMv2 1.15.4-883d4eae、Mininet 2.3.1b4。

测试解释编译JSON；extern/PRE由Python模型提供，临时合成pcap只验证检查器，未归档为真实运行证据。没有用官方Python裁决模型替代P4，也没有从这些离线结果生成原生五场景通过标记。

测试基础设施有两处必要适配：M3离线解释器支持新XOR及runtime-local参数表达式；M6源码不变检查允许新增的那一次故障安装调用，同时仍逐项严格比较所有原路由/角色/PRE/源调度语句。官方验收及数量/counter条件完全未改。

## G. 普通 Ubuntu 官方五场景命令（待执行）

先保存旧证据并退出已有Mininet。普通Ubuntu终端执行：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
make stop
make clean
mkdir -p evidence/final-runtime
set -o pipefail
git --git-dir=.course-git --work-tree=. rev-parse HEAD > evidence/final-runtime/revision.txt
make build 2>&1 | tee evidence/final-runtime/build.log
python3 run-poly-tests.py 2>&1 | tee evidence/final-runtime/official-five.log
```

**以下为目标输出，尚未在本轮取得：**

```text
SCENARIO_PASS no-fault
SCENARIO_PASS reverse
SCENARIO_PASS corrupt-mode1
SCENARIO_PASS drop-mode2
SCENARIO_PASS no-majority
ALL_SCENARIOS_PASS 5
```

官方脚本每场新启动Mininet、控制器重装流水线，结束后退出、make stop、make clean，清除规则和register。不要与其他手工拓扑同时运行。

脚本目前等待POLY_LISTEN，但接收脚本是在sniff打开抓包socket前打印该行，存在启动竞争的可能。本轮无原生复现证据，因此未改官方脚本或接收器。若真实自动测试失败，先保留完整日志，区分接收未就绪、路径未到达和裁决/内容错误；只有证据确定为就绪问题时再增加明确启动同步，仍保留所有接收数量、counter及成功判定。

## H. 每场原始 pcap 的保存与核查

官方脚本finally会清理pcaps，所以仅运行上节不会保留每场原始抓包。为提供故障发生的直接证据，按本节在新拓扑中逐场手工复测并归档。先做corrupt-mode1，再对其他场景重复完整步骤；**每场退出、归档后make stop/make clean，再开始下一场。**

终端A（每个终端将final_case设为同一场景）：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
final_case=corrupt-mode1
mkdir -p "evidence/final-runtime/$final_case"
set -o pipefail
git --git-dir=.course-git --work-tree=. rev-parse HEAD > "evidence/final-runtime/$final_case/revision.txt"
make build 2>&1 | tee "evidence/final-runtime/$final_case/build.log"
make 2>&1 | tee "evidence/final-runtime/$final_case/mininet.log"
```

终端B，在十台交换机启动后：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
final_case=corrupt-mode1
final_fault_args=()
case "$final_case" in
    no-fault|reverse) ;;
    corrupt-mode1) final_fault_args=(--fault corrupt:1:1:0x1) ;;
    drop-mode2) final_fault_args=(--fault drop:2:1) ;;
    no-majority) final_fault_args=(--fault corrupt:1:1:0x1 --fault corrupt:2:1:0x2 --fault corrupt:3:1:0x4) ;;
    *) echo "unknown final_case" >&2; exit 1 ;;
esac
set -o pipefail
python3 mycontroller.py "${final_fault_args[@]}" 2>&1 | tee "evidence/final-runtime/$final_case/controller.log"
```

确认控制器无错误后，在Mininet提示符执行下列三组中的一组。

正向no-fault/corrupt-mode1/drop-mode2：

```text
h2 sh -c 'python3 -u receive-poly.py --timeout 10 --expect 1 > /tmp/poly-final-recv.log 2>&1 &'
sh sleep 1
h1 python3 send-poly.py 10.0.2.2 auto-corrupt
sh sleep 11
h2 cat /tmp/poly-final-recv.log
```

上例message用于corrupt-mode1；no-fault改为auto-ok，drop-mode2改为auto-drop，各场仍只发一次。

反向reverse：

```text
h1 sh -c 'python3 -u receive-poly.py --timeout 10 --expect 1 > /tmp/poly-final-recv.log 2>&1 &'
sh sleep 1
h2 python3 send-poly.py 10.0.1.1 auto-reverse
sh sleep 11
h1 cat /tmp/poly-final-recv.log
```

no-majority：

```text
h2 sh -c 'python3 -u receive-poly.py --timeout 4 --expect 0 > /tmp/poly-final-recv.log 2>&1 &'
sh sleep 1
h1 python3 send-poly.py 10.0.2.2 auto-no-major
sh sleep 5
h2 cat /tmp/poly-final-recv.log
```

手工sleep用于给接收器启动留出时间，不是对官方判定条件的修改。仍需保存接收日志、源POLY_SEND内容及pcap，不能只看接收器提前停止后的received=1。

终端C，拓扑保持运行时读取真实counter和注入表：

```bash
cd /home/p4/p4-poly-work/p4-poly-lab
source ~/p4setup.bash
final_case=corrupt-mode1
set -o pipefail
python3 read-counters.py 2>&1 | tee "evidence/final-runtime/$final_case/counters.log"
python3 evaluate-counters.py "evidence/final-runtime/$final_case/counters.log" | tee "evidence/final-runtime/$final_case/feedback.log"
printf 'table_dump MyIngress.polymorphic_fault\n' | simple_switch_CLI --thrift-port 9092 | tee "evidence/final-runtime/$final_case/s11-fault.log"
printf 'table_dump MyIngress.polymorphic_fault\n' | simple_switch_CLI --thrift-port 9094 | tee "evidence/final-runtime/$final_case/s21-fault.log"
printf 'table_dump MyIngress.polymorphic_fault\n' | simple_switch_CLI --thrift-port 9096 | tee "evidence/final-runtime/$final_case/s31-fault.log"
```

Thrift端口按本工程顺序：s11=9092、s21=9094、s31=9096；若启动日志不同，以日志为准。

终端A执行exit，正常停止交换机以刷新pcap，随后终端C：

```bash
cp pcaps/*.pcap "evidence/final-runtime/$final_case/"
cp /tmp/poly-final-recv.log "evidence/final-runtime/$final_case/receiver.log"
python3 tests/check_final_pcaps.py --scenario "$final_case" --pcap-dir "evidence/final-runtime/$final_case" --counters "evidence/final-runtime/$final_case/counters.log" 2>&1 | tee "evidence/final-runtime/$final_case/pcap-check.log"
make stop
make clean
```

更换所有终端中的final_case，按相同流程复测其余场景。最终也可对已归档文件统一重查（反向按scenario自动选择方向）：

```bash
final_failed=0
for final_case in no-fault reverse corrupt-mode1 drop-mode2 no-majority; do
    python3 tests/check_final_pcaps.py --scenario "$final_case" --pcap-dir "evidence/final-runtime/$final_case" --counters "evidence/final-runtime/$final_case/counters.log" || final_failed=1
done
test "$final_failed" -eq 0
```

新检查器不会修补原始包或把source CRC替换成observed CRC。它直接解码原始字节，分别记录两种CRC，并检查：

1. 一份原始输入，源三出口均为sequence1、C0及原始内容。
2. 正确物理路径上注入节点**入口仍为原文**；其出口出现精确128bit XOR结果，或从该出口开始副本消失。
3. 下游每一跳及目的入口保持该结果；source_crc32始终为C0，no-majority实际observed CRC互异。
4. drop场景不仅目的入口缺失，注入节点出口及之后所有点也必须缺失；文件本身仍须存在，不能把漏抓包当丢包证据。
5. 目的主机出口精确为1份原文或0份；无外层泄漏，MAC/checksum正确，没有重复输出。
6. 两端counter精确符合清洁场景预期，尤其缺失模态bad=0。

正常M4/M6检查器保留原严格CRC一致性要求；故障场景使用新增检查器，不放宽旧工具。新检查器只覆盖官方场景的MASK/SEQ组合；支持--direction覆盖，用于另行探测反向故障，但不把这些扩展探测写成官方五场景通过。

## I. 普通协议回归与已知限制

在独立无故障拓扑或手工no-fault场景中补充：

```text
h1 ip -4 neigh flush dev eth0
h2 ip -4 neigh flush dev eth0
pingall
h1 ping6 -c 2 fe80::5678%eth0
h2 ping6 -c 2 fe80::1234%eth0
h1 sh -c 'timeout 60 python3 -u receive.py > /tmp/final-h1-sr.log 2>&1 &'
h2 sh -c 'timeout 60 python3 -u receive.py > /tmp/final-h2-sr.log 2>&1 &'
sh sleep 1
h1 sh -c "printf '4 2 2 1\nq\n' | python3 send-sr.py 10.0.2.2"
h2 sh -c "printf '4 1 1 1\nq\n' | python3 send-sr.py 10.0.1.1"
sh sleep 1
h1 cat /tmp/final-h1-sr.log
h2 cat /tmp/final-h2-sr.log
```

SR需在对端日志看到UDP/4321；仅发送端打印不算到达。保存这些日志，避免把已有IPv4/IPv6通过扩大为SR真实回归已通过。

目前限制：

- 本轮原生五场景、真实故障CRC/丢包位置、故障后主机输出、并发压力尚未验证；AF_INET错误记录在evidence/final/runtime-status.log。
- 官方自动脚本可能有接收启动竞争，尚未在本轮复现；未凭猜测修改。
- 表有1024物理项，每个逻辑规则占同一交换机两方向各一项；超容量由P4Runtime报错，不做隐式截断。
- 故障项是持久精确项，在流水线重装/新进程前不会自动消失；运行控制器重装流水线会重置序号与裁决状态，不是在线增量调整接口。
- 同一配置同时作用两个方向的指定MODE/SEQ；不提供单方向CLI选择。无环固定路径保证每份副本只经过一个注入节点，未实现对任意循环/重注入的去重。
- 沿用M5的1024窗口、32位半序空间和重启约束；CRC不是密码学认证，两个模态相同错误可形成错误多数。本轮未改变这些能力边界。
- 未升级工具链、修改AppArmor、全局tutorials/utils或官方验收预期，没有使用权限绕过。

## J. 文件位置与 Git 提交

| 文件 | 关键内容 |
| --- | --- |
| polymorphic.p4:587 | corrupt/drop真实数据面action |
| polymorphic.p4:597 | exact故障表及const NoAction默认 |
| polymorphic.p4:752 | 完整性校验后的故障表接入 |
| mycontroller.py:31 | Fault参数范围与数据结构 |
| mycontroller.py:51 | --fault语法解析、去重/冲突处理 |
| mycontroller.py:82 | 精确P4Runtime规则构造 |
| mycontroller.py:320 | 仅向s11/s21/s31安装，先于源调度 |
| tests/check_faults.py | 14组离线检查及真实protobuf核对 |
| tests/check_final_pcaps.py | 五场景原始pcap/CRC/位置/出口/counter核对 |
| class3/state-design.txt | 补充最终故障接口及证据状态 |
| evidence/final/ | 完整编译、离线及不变性证据 |

使用现有 `git --git-dir=.course-git --work-tree=.`：

- `07e92f5`：归档用户M6真实前置pcap及实际复查。
- `7cbc1723d9b21a57f9792249086fcc621bc7e7e3`：故障注入实现、控制器、回归、检查器和证据。
- 本报告另行提交，避免递归引用自己的哈希。

未重写历史、配置remote或创建完成标签。既有未跟踪空文件gRPC、h1、h2、pingall保留且未纳入提交。本轮完成后停止，等待用户在普通Ubuntu终端执行最终真实验收。
