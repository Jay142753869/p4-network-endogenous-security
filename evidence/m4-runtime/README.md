# 用户提供的 M4 真实运行证据

对应实现 987429b、报告 7d561f9。目录中的原始 pcap 由用户在普通 Ubuntu/BMv2/Mininet 环境运行后提供，不是合成数据。

本轮按原 tests/check_m4_pcaps.py 实际重新读取：正向 source/full 各 inputs=2、反向 source/full 各 inputs=1，均 M4_PCAP_OK。

| 方向 | sequence | source_crc32 |
| --- | ---: | --- |
| 正向 | 1 | 0xd4c4087e |
| 正向 | 2 | 0x71960faa |
| 反向 | 1 | 0xf1539cb0 |

实际复查日志为 recheck-source/full-forward/reverse.log，原始抓包哈希见 SHA256SUMS。完整检查含三条路径的逐跳、目的网关入口及主机端口无封装泄漏。

普通 IPv4 pingall 和 IPv6 正向通过属于用户报告；IPv6 反向和普通 SR 双向尚需补充，不能宣称全部普通协议回归完成。

这是 M4 的运行证据，不是 M5 裁决或 M6 还原证据。不因本记录创建完成标签。
