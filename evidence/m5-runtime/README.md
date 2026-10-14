# 用户提供的 M5 真实无故障运行证据

来源：用户在普通 Ubuntu / BMv2 / Mininet 环境运行 M5 后提供的原始材料，对应 M5 阶段（最新报告提交 `235c188`）。本次开发未在沙箱重新启动该网络。

- S2：mode1/2/3 各 good=3、bad=0，no_majority=0。
- S1：mode1/2/3 各 good=1、bad=0，no_majority=0。
- S2 slot1：seq_tag=1、seen_modes=7、decision_status=1、decided_crc=1853104259（0x6e742083）。

原始日志为 `counters.log`、`counters-final.log`、`s2-registers.log`，原始抓包共52份。本轮用未修改的 `tests/check_m4_pcaps.py` 复查完整路径：正向3个输入、反向1个输入，均通过，且目的主机口无还原输出，符合当时M5安全丢弃边界。复查日志为 `recheck-forward.log`、`recheck-reverse.log`。

正向seq1/2/3的source_crc32分别为0x6e742083、0xce5a4e91、0x48ffedd5；反向seq1为0x9ccf2f72。seq1正向的CRC与目的register日志一致。哈希见 `SHA256SUMS`。

真实无故障计数与状态日志支持M5前置状态；这些材料不能作为M6透明还原通过的证据，也没有证明故障、重复副本、并发压力或全部普通协议回归完成。
