# 基于 P4 的多模态网络内生安全实验

本项目是在课程原始三模态 Demo 上继续完成的综合实验。网络由 Mininet 和 BMv2 搭建，使用 P4 处理数据包，通过 P4Runtime 控制器配置交换机规则。

目前代码包含 IPv4、IPv6 和 Source Routing 三种模态，以及报文复制、异构封装、2/3 多数裁决、故障注入和原始报文还原。第四、第五模态属于选做内容，本仓库暂未实现。

## 1. 实验环境

- 课程统一镜像：**2026-Aug-01 P4 tutorials**（Ubuntu 24.04）。
- 运行环境：P4_16、BMv2 `simple_switch_grpc`、P4Runtime、Mininet、Python 3。
- 实验数据：IPv4/UDP，目的端口 `5000`，有效数据固定为 16 字节。
- Git 仓库：<https://github.com/Jay142753869/p4-network-endogenous-security>
- 最终 Git commit：**提交最终版本后运行 `git rev-parse HEAD` 填写**，确保与提交的代码、报告和证据一致。

项目使用自带的 `utils/`，不需要覆盖虚拟机中的 `~/tutorials/utils`，也不要自行升级 P4 工具链。只有在当前终端找不到 `p4c` 或 `simple_switch_grpc` 时，才执行：

```bash
source ~/p4setup.bash
```

## 2. 主要文件

| 文件 | 用途 |
| --- | --- |
| `polymorphic.p4` | Parser、Ingress 调度、Egress 封装、目的网关裁决及报文还原 |
| `mycontroller.py` | 安装转发表、multicast group、目的网关规则和故障规则 |
| `topo/topology.json` | 两台主机、十台交换机及链路配置 |
| `send-poly.py`、`receive-poly.py` | 发送固定格式 UDP 数据、检查接收内容和份数 |
| `run-poly-tests.py` | 五个独立的综合验收场景 |
| `read-counters.py`、`evaluate-counters.py` | 读取各模态 good/bad、无多数统计并生成反馈 |
| `send.py`、`receive.py`、`send-sr.py` | 原始 IPv6、SR 路径检查 |
| `BASELINE_README.md` | 第一次实验的原始三模态 Demo 参考操作 |
| `evidence/` | 编译、离线回归、抓包和其他阶段性记录，需按文件说明区分证据类型 |

`STUDENT_TODO.md`、`IMPORT_README.md` 和 `DEVELOPMENT_*.md` 保留了起始骨架及开发过程的说明，并不代表当前主分支仍未实现对应功能。

## 3. 三模态转发过程

原始 Demo 的三条路径如下：

| 模态 | h1 → h2 路径 |
| --- | --- |
| IPv4 | `h1 → s1 → s11 → s12 → s2 → h2` |
| IPv6 | `h1 → s1 → s21 → s22 → s2 → h2` |
| Source Routing | `h1 → s1 → s31 → s32 → s2 → h2` |

综合实验中，主机只发出一份普通 IPv4/UDP 报文：

1. 源网关 `s1`（反向为 `s2`）识别 UDP/5000 实验流量，为原报文分配序号并计算 CRC32。
2. Ingress 设置 multicast group，PRE 将报文复制到出口端口 2、3、4；Egress 分别封装为 IPv4、IPv6 和 Source Routing 报文。
3. 目的网关根据序号关联副本，对实际收到的内层字段重新计算 CRC。**不同模态的两份结果一致**时形成 2/3 多数。
4. 只有形成多数的当前副本会恢复为普通 IPv4/UDP 报文并发往目的主机；重复或迟到的副本不会再次输出。若三份结果各不相同，则不输出。

CRC 覆盖内层 IPv4 源/目的地址、协议号、UDP 源/目的端口以及固定 16 字节数据，不包含逐跳变化的外层字段。源端写入的 `source_crc32` 是参考信息，目的网关使用自己计算的 CRC 参与裁决。

## 4. 编译和启动

在课程虚拟机中进入仓库根目录。先确认旧的 Mininet 实验已经退出并清理。

终端 A：

```bash
make
```

看到 `mininet>` 后保持运行。另开终端 B，在相同目录执行控制器：

```bash
python3 mycontroller.py
```

控制器下发表项后，可在 Mininet 中做基础回归：

```text
mininet> pingall
mininet> h1 ping6 -c 3 fe80::5678%eth0
mininet> h2 ping6 -c 3 fe80::1234%eth0
mininet> xterm h1 h2
```

在 `h2` 的 xterm 中先运行接收程序：

```bash
python3 receive-poly.py --timeout 10 --expect 1
```

再在 `h1` 的 xterm 中发送：

```bash
python3 send-poly.py 10.0.2.2 hello
```

无故障时，预期 `h2` 收到内容正确的一份数据。反向测试改为在 `h1` 接收，在 `h2` 执行 `python3 send-poly.py 10.0.1.1 hello`。

原始 SR Demo 的正向端口栈为 `4 2 2 1`，反向为 `4 1 1 1`；详细操作见 `BASELINE_README.md`。路径是否正确还需要查看 `pcaps/` 中的实际报文，不能只依据主机成功接收来判断。

## 5. 故障注入与验收

控制器支持按模态和序号指定故障，例如：

```bash
python3 mycontroller.py --fault corrupt:1:1:0x1
python3 mycontroller.py --fault drop:2:1
```

以上是**两个独立示例**，分别表示篡改模态 1 的序号 1 报文、丢弃模态 2 的序号 1 报文。切换场景前应先退出并清理原有实验，再重新启动和安装规则。

第三次实验要求的五个场景为：

| 场景 | 预期结果 |
| --- | --- |
| 正向无故障 | `h2` 收到正确报文 1 份 |
| 反向无故障 | `h1` 收到正确报文 1 份 |
| 单模态篡改 | 其余两份形成多数，收到原文 1 份 |
| 单模态丢包 | 另外两份一致，收到原文 1 份 |
| 三份各不相同 | 目的主机收到 0 份，`no_majority` 计数增加 |

手工检查计数器时，在网络仍在运行的情况下执行：

```bash
python3 read-counters.py
python3 read-counters.py | python3 evaluate-counters.py
```

自动测试前，先关闭手工启动的 Mininet 并清理：

```bash
make stop
make clean
python3 run-poly-tests.py
```

也可以用 `python3 run-poly-tests.py no-fault` 单独测试一个场景。验收时需要同时核对接收数量、内容、各模态统计和实际抓包，不能只依据测试脚本名称判断是否通过。

## 6. 当前验证情况与限制

仓库保留了 P4 编译和离线测试记录，主要位于 `evidence/`。其中 `evidence/final/runtime-status.log` 记载：当时运行环境不允许创建所需网络 socket，**原生 BMv2 五场景没有在该环境中执行**。这些离线记录不能替代课程要求的真实 Mininet、BMv2 运行与抓包验收；最终提交前应在课程虚拟机中重新验证并补齐证据。

本实现使用固定 16 字节 UDP 数据，不是通用的任意长度报文处理方案。CRC32 主要用于实验中的错误检测，不是密码学认证；2/3 多数也无法保证抵抗两个模态发生相同错误的情况。裁决状态由有限大小的寄存器保存，序号复用和长时间连续发送仍需结合实际流量验证。

## 7. 退出与提交

结束后先退出 Mininet，再在项目根目录清理：

```bash
make stop
make clean
```

最终提交时，按第三次实验指导书将本仓库需要的完整源代码放入 `codes/`，并把本 README 放在 `codes/README.md`。报告和 `evidence/` 应对应同一个最终 Git commit。只选取能说明结论的截图、pcap、日志和统计文件，不必打包可重新生成的 `build/`、`logs/`、`pcaps/` 全目录。历史阶段可根据实际完成情况核对 `class1-baseline`、`class2-multicast`、`class3-adjudication` 和 `class4-final` 标签。
