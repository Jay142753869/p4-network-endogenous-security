# 用户提供的 M6 真实无故障前置证据

用户在普通 Ubuntu / BMv2 / Mininet 中完成 M6 正反向测试后提供本目录材料；代码阶段对应 M6（实现526e5dd，报告888db03）。本次沙箱没有重新启动该网络。

原始pcap共52份，counter日志为counters.log。本轮用未修改的tests/check_m6_pcaps.py实际复查，正反向均为inputs=1、modalities=3、host_outputs=1、per_sequence=1，并核对完整内容、MAC、checksum及counter。

- 正向sequence1：source_crc32=0x93d25cf1，protected_hex=6d362d666f7277617264000000000000。
- 反向sequence1：source_crc32=0x48f21ff4，protected_hex=6d362d72657665727365000000000000。
- 两端各模态good=1、bad=0、no_majority=0。

复查输出见recheck-forward.log、recheck-reverse.log，原始文件及复查文件哈希见SHA256SUMS。

用户同时报告正反向POLY_RECV index=1、POLY_SUMMARY received=1 expected=1，以及普通IPv4/IPv6双向真实通信通过；对应接收/普通协议终端日志未包含在本目录，不能将其描述为本轮亲自执行的结果。普通SR双向仍缺明确的真实回归记录。

这是真实M6无故障前置材料，不是本轮故障注入或官方五场景通过的证据。
