# 第一阶段开发报告：M1 / M2

本轮完成协议头、Parser 和对应 Deparser 线序；停止于 M2。
未实现 M3–M6，未启动故障注入，未运行或修改实验三五场景验收。

## 项目检查与原始版本

已阅读 `STUDENT_TODO.md`、实验二官方指导全文（重点为 2.1、2.6、3.3–3.5）、实验三官方指导全文及 `reference/experiment2/poly_headers.p4.inc`。
实验三要求目的网关重新计算 observed CRC、按不同模态投票和透明还原，这些均保留到后续阶段。

原始结构共 85 个文件，完整清单见 `evidence/m1-m2/initial-files.txt`。主要结构：

```text
polymorphic.p4                  P4_16 / v1model 数据面骨架
mycontroller.py                 P4Runtime 控制器
STUDENT_TODO.md                 M1–M6 字段与接口约定
Makefile → utils/Makefile       编译与 Mininet 运行入口
topo/topology.json              两端网关与多条中间路径
utils/                         课程本地工具及 P4Runtime 库
send*.py / receive*.py          普通协议、SR、UDP/5000 收发脚本
run-poly-tests.py               实验三自动场景
read-counters.py / evaluate-counters.py
reference/experiment2/          PolyShim 与 multicast 接口
reference/experiment3/          裁决接口和 Python 模型
materials/                     两份指导 PDF、参考结果、提交模板
```

原 P4 由 EtherType 分流，SR 栈解析到 BOS 后提取普通 IPv4；Ingress 保留 IPv4/IPv6 查表、ARP 响应和 SR 弹栈，Egress 尚未封装。原 Deparser 没有 PolyShim、内层 IPv4 或保护数据。
控制器安装各交换机流水线、两端 ARP 和双向 IPv4/IPv6 路由，SR 路径由主机端口栈提供；没有调度表和 multicast group。本轮不需要更改控制器接口。

初始 `git status` 确认当前不是有效 Git 仓库。`git init` 因环境提供的 `.git/` 只读而失败；随后在允许写入的 `.course-git/` 建立独立 Git 元数据目录。使用方式：

```bash
git --git-dir=.course-git --work-tree=. status
git --git-dir=.course-git --work-tree=. log --oneline
```

原始起步提交为 `1e739c0`，M1 提交为 `5a7a745`。提交作者标为 Codex。
原始提交未含 `build/`、`logs/`、`pcaps/` 或 Python cache；独立 Git 元数据及环境保留目录通过 `.course-git/info/exclude` 排除。
未创建 `class2-multicast` 等完成标签。

## A. M1 具体修改

`polymorphic.p4:12` 定义 `POLY_MAGIC=0x504f`、`POLY_IP_PROTOCOL=253`、`POLY_UDP_PORT=5000`。

`polymorphic.p4:129` 按官方字段次序定义 112 bit（14 字节）的 `polyShim_t`：

| 字段 | 位宽 | 含义 |
| --- | ---: | --- |
| magic | 16 | 0x504f，ASCII PO |
| direction | 8 | 0 为 h1→h2，1 为 h2→h1 |
| sequence_number | 32 | 同一原包副本的共享序号 |
| modality_id | 8 | IPv4=1、IPv6=2、SR=3 |
| source_crc32 | 32 | 源网关参考 CRC |
| inner_ether_type | 16 | 本实验内层 IPv4，0x0800 |

`polymorphic.p4:138` 定义 `protected_data_t.value` 为 `bit<128>`，固定 16 字节。
`polymorphic.p4:148` 将 `poly`、`inner_ipv4` 和 `protected_data` 加入 headers。
`hdr.ipv4` 用于普通或外层 IPv4，`hdr.inner_ipv4` 是独立实例；解析内层不会覆盖外层地址、TTL 或 checksum。

`polymorphic.p4:453` 调整 Deparser：有效的外层头之后依次输出 PolyShim、inner IPv4、传输层、protected data；无效头不输出。
原始普通报文不会凭空增加新协议头。未实现封装时的赋值或恢复动作。

## B. M2 具体修改

| 输入 | Parser 路径与结果 |
| --- | --- |
| 普通 IPv4 | IPv4 → TCP / UDP / accept；ICMP 等负载保持原样 |
| 普通 IPv6 | IPv6 → accept，原有负载保持原样 |
| ARP | 原 parse_arp，保留目的地址 metadata |
| 原 SR | SR 栈 → BOS → lookahead → 普通 IPv4 |
| 主机实验包 | IPv4(protocol=17) → UDP(dport=5000, length=24) → 16 字节数据 |
| IPv4 模态 | IPv4(protocol=253) → PolyShim → inner IPv4 → UDP → 数据 |
| IPv6 模态 | IPv6(nextHdr=253) → PolyShim → inner IPv4 → UDP → 数据 |
| SR 模态 | SR 栈 → BOS → magic=0x504f → PolyShim → inner IPv4 → UDP → 数据 |

SR 使用不消耗报文字节的 16 bit lookahead；合法普通 IPv4 的首半字节为 4，与 PolyShim magic 区分。
非 UDP/5000 不提取保护数据；UDP/5000 的非 16 字节负载也保持为普通负载，不参与固定格式解析。

普通 IPv4 仅在 IHL=5、无 MF、fragment offset=0 时继续解析传输层；options 和分片保持为原始负载，避免从错误偏移读取 UDP。
内层限定 IPv4、IHL=5、无分片、protocol=17。PolyShim 校验 magic 和 inner EtherType。
错误通过 `verify()` 写入 parser error；首次使用显式 `reject` 的版本出现 BMv2 unsupported warning，已修正。

Header 有效性检查：

| 合法输入 | 主要有效头 | 新增头中应无效的实例 |
| --- | --- | --- |
| 普通实验包 | ethernet, ipv4, udp, protected_data | poly, inner_ipv4 |
| IPv4 模态 | ethernet, ipv4, poly, inner_ipv4, udp, protected_data | ipv6, SR 栈 |
| IPv6 模态 | ethernet, ipv6, poly, inner_ipv4, udp, protected_data | ipv4, SR 栈 |
| SR 模态 | ethernet, SR 栈, poly, inner_ipv4, udp, protected_data | ipv4, ipv6 |

离线正常用例均检查有效头集合及 Parser→Deparser 字节一致性；这项检查不执行 Ingress/Egress。

## C. 文件与代码位置

| 文件 | 位置 / 用途 |
| --- | --- |
| polymorphic.p4 | 12：常量；25：Parser error；129：PolyShim；138：保护数据；148：headers；165：Parser；453：Deparser |
| tests/check_m2_parser.py | 新增离线测试，解释编译后的 Parser/Deparser JSON，使用标准库构造报文字节 |
| evidence/m1-m2/ | 原始文件清单、三个阶段编译日志、M2 首次警告日志、离线检查、版本与哈希、运行受限记录 |
| DEVELOPMENT_M1_M2.md | 本报告 |

`mycontroller.py`、Ingress、Egress、checksum control、项目内 `utils/`、拓扑、参考材料和实验三验收脚本均未改动；未修改全局 tutorials/utils。

## D. 实际编译与检查结果

| 阶段 | 实际命令 | 退出码 | 结果 |
| --- | --- | ---: | --- |
| 原始骨架 | make build | 0 | 编译成功 |
| M1 | make build | 0 | 编译成功；新增常量暂未使用 |
| M2 首次 | make build | 0 | 编译成功，但有显式 reject 不支持的警告 |
| M2 修正后 | make build | 0 | 编译成功，仅原有 5 项未使用 ARP 常量警告 |
| 离线报文检查 | python3 tests/check_m2_parser.py | 0 | 34 个用例通过 |
| Python 语法 | python3 -m py_compile … | 0 | 控制器、相关脚本和新增检查共 7 个文件通过 |
| 差异检查 | git … diff --check | 0 | 无空白错误 |

所有 `make build` 均实际调用了 `p4c-bm2-ss --p4v 16`，生成 `build/polymorphic.json` 和 `build/polymorphic.p4.p4info.txtpb`。
材料时间戳超前还导致 Make 的 future modification time / Clock skew 提示；没有改动材料时间戳。最终源码和产物 SHA256 记录于 `verification.txt`。

沿用当前课程环境的预装工具，未安装、升级或替换：p4c **1.2.5.15**（cdd7205767）、BMv2 **1.15.4-883d4eae**、Mininet **2.3.1b4**、Ubuntu **24.04.4 LTS**。
构建接口与材料指定的 2026-Aug-01 环境一致；本次没有取得可独立核实镜像发行日期的标识，不把版本号当作镜像日期证明。

34 个离线用例覆盖普通协议、UDP 端口与长度、IPv4 options/分片、SR 1/4/9 跳、三模态双向字段、外内 IPv4 独立性、异常 magic/内层类型、截断和栈溢出。
此检查仅解释 p4c JSON 中本阶段用到的有限操作，不是 BMv2 执行结果。

尝试运行检查时，Scapy 在创建 socket 时报 `Operation not permitted`；BMv2 文件模式在 nanomsg bind 时同样被环境拒绝，进程退出 134。
没有获得实际报文处理结果，也没有获得 ping、IPv6 或 SR 连通性结果。原始启动输出保存在 `runtime-blocked.log`。

## E. 当前风险与限制

1. 仍需在允许网络实验的课程虚拟机终端运行普通 ping、双向 IPv6、ARP 和原 SR 回归；本轮不能宣称运行回归通过。
2. BMv2 的 Parser 错误不会自动等价于最终丢弃。原 Ingress 未检查 `standard_metadata.parser_error`；M3 接入时应先明确错误丢弃及实验包有效性条件。
3. 当前支持固定、无 options、无分片的内层 IPv4/UDP/16 字节数据；没有增加 IPv6 扩展头遍历、IP/UDP 长度一致性或 checksum 验证。
4. direction 和 modality_id 按原位宽提取，尚未验证取值范围或与外层模态的一致性；后续网关识别不能只依赖 poly.isValid()。
5. 原 `srcRoute_finish()` 假设 SR 后面是普通 IPv4。新的 SR/PolyShim 报文到目的网关时，后续目的网关分支必须先于该普通 SR 终止逻辑处理，避免错标 EtherType 后送主机。本轮未实现目的网关控制逻辑。
6. M3–M6 尚未实现，因此没有 sequence 分配、CRC、复制、封装、裁决或透明还原；本阶段编译和离线结果不代表综合实验完成。

## F. 下一阶段 M3 建议

先补 Parser 错误处理，再用主机入口、目的 IPv4、UDP/5000、固定长度数据有效性和“无 PolyShim”共同识别原始实验流量，防止内部副本被再次调度。

在 Ingress 为每个原始包只分配一次序号，确定 direction，保存 `hdr.ipv4` 至独立 `hdr.inner_ipv4`，再准备 PolyShim。
CRC 按官方顺序覆盖内层源/目的 IPv4（32+32）、协议号（8）、UDP 源/目的端口（16+16）、保护数据（128），合计 232 bit；后续目的网关用相同字段顺序重算 observed CRC，排除 TTL 等逐跳变化字段。

按官方接口加入 `MyIngress.polymorphic_schedule`，在两个方向的源网关设置 `mcast_grp=10`；控制器为 S1/S2 各配置 `(2,1)、(3,2)、(4,3)`。
每步实际编译并核对 P4Info，随后在可运行 Mininet 的环境观察三份共享 sequence/CRC 的副本。三种 Egress 外层封装留在 M4 完成。

本阶段到此停止，等待下一步指令。
