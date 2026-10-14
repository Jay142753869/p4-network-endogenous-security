# M3 首次真实 BMv2 运行证据

来源：用户在普通 Ubuntu 终端完成运行后提供的结果及本目录六份源网关出口 pcap；对应实现提交 d7284f6，报告提交 4f886aa。不是 Python 模型或合成抓包。

用户报告：make build 成功、10 台 BMv2 交换机成功启动、Mininet pingall 0% dropped。当前未提供这些命令的完整终端原始日志，因此这些三项记录明确归属于用户报告。

| 方向 | 源网关 | 每个出口份数 | 总副本数 | sequence | source_crc32 |
| --- | --- | ---: | ---: | ---: | --- |
| 0，h1→h2 | S1 | 1 | 3 | 1 | 0xee6384ce |
| 1，h2→h1 | S2 | 1 | 3 | 1 | 0xc20d78ca |

本轮已用未改动的 tests/check_m3_pcaps.py 重新读取六份原始 pcap，两方向均 PCAP_CHECK_OK，且序号/CRC 与用户报告一致。实际复查输出见 pcap-recheck-forward.log 和 pcap-recheck-reverse.log；原始 pcap 哈希见 SHA256SUMS。

这些证据仅证明 M3 源网关三出口复制、序号与 CRC 一致；不证明 M4 三种异构封装、三条路径或目的主机输出正确。不据此创建 class2-multicast 标签。
