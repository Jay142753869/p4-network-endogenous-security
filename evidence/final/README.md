# 最终阶段证据范围

本轮没有原生BMv2五场景运行结果；runtime-status.log记录实际AF_INET socket被拒绝。

- build-00至04：基线、故障表、控制器、离线测试和最终检查阶段实际make build输出，全部退出0。
- phase2-m*、final-m*：实际M2至M6离线回归输出。
- fault-offline.log：14组离线检查，包括编译JSON故障action、真实P4Runtime protobuf构造和临时合成pcap检查器夹具；不是原生五场景验收。
- verification.txt：语法、差异、工具版本、既有文件/编译指令不变及哈希记录。
- p4info-contract.txt：五张既有表、公开action和counter接口不变，以及新增故障表/action实际P4Info。
- crc-expectations.txt：232bit CRC的数学预期关系，不是任何新场景的真实CRC测量。
- m6-recheck-*.log：对用户旧M6真实抓包的实际复查；原始材料和来源见../m6-runtime/。不属于本轮故障运行证据。

未保存合成pcap为真实运行材料，未输出或伪造原生SCENARIO_PASS。待执行命令及限制见根目录DEVELOPMENT_FINAL.md。
