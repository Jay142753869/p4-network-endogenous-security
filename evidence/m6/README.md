# M6 验证材料的范围

- `build-00/01/02/03-*.log`：本轮实际 P4 编译完整输出；阶段分别是M5基线、尚未接入的header还原、接入accept门控和主机出口、完整检查版本。
- `phase1-*`、`phase2-*`、`final-*`：各阶段实际执行M2/M3/M4/M5离线回归的输出。
- `m6-offline.log`：13组M6离线检查。解释编译JSON，CRC/checksum/register/PRE等为Python模型；pcap检查器使用临时合成夹具，未把夹具保存为真实证据。
- `verification.txt`：Python语法、差异检查、工具版本、受保护文件不变及编译后的M3/M5 action、register/counter/Parser/Deparser/checksum/calculation语义不变核对，以及关键文件哈希。
- `p4info-contract.txt`：与M5编译基线逐个比较，五张既有表、两个公开action、三个counter接口保持不变。
- `runtime-status.log`：实际AF_INET socket创建被拒绝，本轮M6原生BMv2/Mininet没有运行。
- `m5-runtime-recheck-*.log`：对用户提供的旧M5真实pcap进行路径复查，不是M6运行结果；原始材料及来源说明在`../m5-runtime/`。

本目录没有M6真实抓包或原生收发成功结果。完整设计、待执行的Ubuntu命令和阶段限制见项目根目录`DEVELOPMENT_M6.md`。
