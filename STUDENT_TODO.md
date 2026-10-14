# 学生实现接口与 TODO

本文给出实现边界、字段约定和伪代码，不提供可直接复制的完整答案。每个阶段都应先编译，再用抓包或计数器确认行为。

## 使用方法与课次对应

先在代码中搜索 `TODO M1`—`TODO M6`，再按对应课次完成：

| 里程碑 | 对应课次与任务 |
| --- | --- |
| M1、M2 | 第 2 次课任务 1：协议字段和 Parser |
| M3 | 第 2 次课任务 2、3：sequence、CRC、调度和 multicast |
| M4 | 第 2 次课任务 4、5：三模态 Egress 封装和路径验证 |
| M5 | 下次实验：目的网关状态、2/3 多数、统计和反馈 |
| M6 | 下次实验：透明还原和单一输出 |

`mycontroller.py` 中同一 TODO 区域还包含目的网关角色和故障表项提示，分别在后续裁决与综合完善阶段完成。更细的“文件—标记—任务”对照见《第二次实验指导》的“学生任务与过程要求”和《第三次实验指导》的对应任务表。

## M1：协议字段

在 `polymorphic.p4` 中新增以下逻辑字段。位宽可直接采用本约定，以保持课程测试格式一致。

```p4
const bit<16> POLY_MAGIC       = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL = 253;
const bit<16> POLY_UDP_PORT    = 5000;

header polyShim_t {
    bit<16> magic;
    bit<8>  direction;       // 0: h1 -> h2, 1: h2 -> h1
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type;
}

header protected_data_t {
    bit<128> value;
}
```

还需要一个独立的 `inner_ipv4` header 保存原 IPv4。不要同时把同一个 header 实例当作 outer IPv4 和 inner IPv4 使用。

其中：

```text
magic = 0x504f
direction = 0 表示 h1->h2，1 表示 h2->h1
inner_ether_type = 0x0800
```

## M2：Parser

入口原始报文格式固定：

```text
Ethernet / IPv4 / UDP(dport=5000) / protected_data(16 bytes)
```

parser 应做到：

- 新增 parser 分支后，普通 IPv4、IPv6、ARP 和 Source Routing 报文仍能按原有逻辑正常处理。
- UDP 目的端口不是 5000 时，不误解析 protected data。
- 三种外层报文都能到达 `PolyShim -> inner IPv4 -> UDP -> protected data`。
- parser 不执行多数裁决，只负责形成统一 header 视图。

## M3：调度和 multicast

### P4 侧

建议表接口：

```p4
table polymorphic_schedule {
    key = {
        standard_metadata.ingress_port: exact;
        hdr.ipv4.dstAddr: exact;
        hdr.udp.dstPort: exact;
    }
    actions = {
        start_polymorphic;
        NoAction;
    }
}
```

`start_polymorphic` 标记报文需要封装并写入方向；随后的入口逻辑至少完成：

1. 为一个原始报文分配一个 sequence。
2. 按实验指导规定的字段范围计算 `source_crc32`：内层 IPv4 源/目的地址和协议号、UDP 源/目的端口、固定 16 字节 protected data。
3. 保存 inner IPv4 并设置 PolyShim。
4. 设置 `standard_metadata.mcast_grp = 10`。

### 控制器侧

P4Runtime multicast group 的调用约定：

```python
writeMulticastGroup(
    p4info_helper,
    switch,
    group_id=10,
    replicas=[(2, 1), (3, 2), (4, 3)],
)
```

其中元组是 `(egress_port, instance)`。PRE 根据 `egress_port` 把副本送到对应出口，并把 `instance` 作为副本编号写入 Egress 可读取的 `egress_rid`。本实验的三种封装按 `egress_port` 选择；instance 使用 1、2、3，便于抓包和排查时区分副本。

S1 和 S2 都要建立 group 10，才能支持双向调度。

## M4：三种 Egress 封装

PRE 已经为每个副本确定出口。Egress 读取只读的 `standard_metadata.egress_port`，按端口生成对应封装：

| 端口 | 模态 | modality id | 检查点 |
| ---: | --- | ---: | --- |
| 2 | outer IPv4 | 1 | 外层地址能沿 s11、s12 转发 |
| 3 | outer IPv6 | 2 | next header 和地址正确 |
| 4 | Source Routing | 3 | 正向/反向 SR 栈正确 |

必须保证三份副本的 `sequence_number` 和 `source_crc32` 相同。抓包先看三条入口出口，不要直接跳到目的主机结果。

## M5：2/3 多数裁决

建议以 `sequence_number % REGISTER_SIZE` 选择 slot，并用 `seq_tag` 判断 slot 是否属于当前报文。每个 slot 至少需要：

```text
seq_tag
crc_candidate_1
crc_candidate_2
mode_candidate_1
mode_candidate_2
seen_bitmap
candidate_count
decided
winner_crc
```

每个模态使用一个 seen bit。同一 `(sequence, modality)` 再次到达时应丢弃，不能作为第二票。

核心伪代码：

```text
读取 slot
if seq_tag != current sequence:
    初始化 slot

if 当前 modality 已出现:
    drop
else:
    设置对应 seen bit

if 已 decided:
    根据 winner CRC 更新 good/bad
    drop
elif 没有候选:
    保存 candidate 1
    drop
elif 只有 candidate 1:
    if current CRC == candidate 1:
        decided = 1，winner = current CRC，允许当前副本输出
    else:
        保存 candidate 2
        drop
else:
    if current CRC 等于任一候选:
        decided = 1，winner = current CRC，允许当前副本输出
    else:
        no_majority += 1
        drop
```

到达顺序不固定，因此不能假设 mode1、mode2、mode3 按编号依次到达。

### 建议统计接口

```text
mode_good[1..3]
mode_bad[1..3]
no_majority
```

统计属于反馈的必做范围；本轮不根据计数器停用模态。

## M6：恢复和输出

只有形成多数的那个副本可以继续：

1. invalidate 三种 outer header 和 PolyShim。
2. 将保存的 inner IPv4 恢复为最终 IPv4。
3. 恢复 Ethernet EtherType、目的主机 MAC 和正确 checksum。
4. 设置目的主机端口 1。
5. 后续同 sequence 副本只更新统计并 drop。

验证 `receive-poly.py --expect 1`，不要只用 Wireshark 目测“似乎只有一份”。

## 最小自检表

| 阶段 | 输入 | 预期 |
| --- | --- | --- |
| M2 | 普通 ping/IPv6/SR | 三项原有功能均成功，新增 parser 分支未影响它们 |
| M3 | 一份 UDP/5000 参考输入，或本组 TCP 实验输入 | 端口 2/3/4 各一份同 sequence 副本 |
| M4 | 一份 UDP/5000 参考输入，或本组 TCP 实验输入 | 三条外层封装均能走到对端网关 |
| M5 | 无故障 | 形成多数且只选择一次 |
| M5 | 单模态篡改 | 两份正确副本胜出，异常模态 bad |
| M5 | 单模态丢包 | 两份一致副本仍胜出 |
| M5 | 三份各异 | 不输出，no-majority 增加 |
| M6 | 完整流程 | 目的主机只收到正确原文一份 |
