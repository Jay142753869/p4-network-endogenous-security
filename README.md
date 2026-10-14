# 三模态综合实验学生代码骨架

## 1. 这份骨架是什么

本目录以已验证的 IPv4、IPv6、Source Routing 原始 demo 为基础，能够在未完成 TODO 时正常编译和复现三条独立路径。

它不是综合实验答案。初始版本还没有实现“同一原包复制三份”和“2/3 多数裁决”，请按 `STUDENT_TODO.md` 分阶段完成。

统一环境：`2026-Aug-01` P4 tutorials 镜像。不要升级 p4c、BMv2、Mininet 或替换项目内 `utils/`。

## 2. 起始文件

| 文件 | 用途 |
| --- | --- |
| `polymorphic.p4` | 可编译的三模态初始代码，含 M1—M6 TODO 定位 |
| `mycontroller.py` | 原始 Demo 的 P4Runtime 表项，含控制面 TODO |
| `send-poly.py` | 材料内 UDP/5000、16 字节输入生成器 |
| `receive-poly.py` | 最终单一输出接收与数量检查 |
| `send.py` / `receive.py` | 原 IPv6 测试脚本 |
| `send-sr.py` | 原 SR 测试脚本 |
| `topo/` / `utils/` | 已适配统一镜像的拓扑和本地工具 |
| `BASELINE_README.md` | 原始 demo 操作说明 |
| `STUDENT_TODO.md` | 分阶段接口、伪代码和自检点 |

## 3. 第一次运行

终端 A：

```bash
cd <本目录>
make
```

若当前终端提示找不到 `p4c`、`simple_switch_grpc` 等命令，再执行一次 `source ~/p4setup.bash` 后重试。

终端 B：

```bash
cd <本目录>
python3 mycontroller.py
```

先按课程任务书验证原始 IPv4、IPv6 和 SR。推荐 SR 端口栈：

```text
h1 -> h2: 4 2 2 1
h2 -> h1: 4 1 1 1
```

结束时：

```bash
make stop
make clean
```

## 4. 综合实验统一输入

先在目的主机启动：

```bash
python3 receive-poly.py --timeout 5 --expect 1
```

再在源主机发送：

```bash
python3 send-poly.py 10.0.2.2 class2-test
```

脚本会把短消息补零到固定 16 字节；UTF-8 编码后超过 16 字节会拒绝发送。完成综合实验后，接收端应只看到一份还原后的 IPv4/UDP 报文。这是材料内的 UDP 参考路线；小组可以改用 TCP，但需要让收发脚本、Parser、CRC 和最终还原保持一致。

## 5. 建议开发节奏

每完成一个里程碑都执行一次编译，必要时保存 pcap：

```bash
make build
```

推荐顺序：

1. M1—M2：新增 header 和 parser，再次运行普通 IPv4、IPv6、ARP 和 Source Routing 检查，确认原有功能仍然正常。
2. M3：只实现入口识别、sequence、CRC 和 multicast，先观察三份副本。
3. M4：分别完成三个 Egress 外层封装，逐端口抓包。
4. M5：先做无故障多数裁决，再增加重复、篡改、丢包和无多数。
5. M6：恢复 inner IPv4，验证目的主机只收到一份。

每阶段建议单独 commit，并使用任务书规定的阶段 tag。

## 6. 完成定义

```text
源主机发送 1 份
-> 入口交换机复制 3 份
-> IPv4 / IPv6 / SR 三条路径
-> 目的网关完成 2/3 多数裁决
-> 目的主机收到正确原文 1 份
```

把三个不同协议包分别从主机发送，或把裁决放在主机 Python 程序中，均不等价于本实验目标。

## 7. Git 建议

仓库应忽略运行产物；本目录已经提供 `.gitignore`。不要提交整个 `build/`、`logs/`、`pcaps/` 或 Python cache。需要验收的少量日志与抓包整理到 `evidence/`。
