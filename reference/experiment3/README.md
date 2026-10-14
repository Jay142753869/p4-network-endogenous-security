# 裁决、扩展与综合验收代码说明

本次课从第 2 次课实验仓库继续开发，不另发完整 P4 答案。

- `接口示例/adjudication_state.p4.inc` 给出统一 register/counter 声明，复制到 `polymorphic.p4` 的 `MyIngress` 后补全算法。
- `接口示例/adjudication_model.py` 是可直接执行的 Python 状态机模型，用于先理解乱序、重复、篡改、丢包和无多数，再翻译成 P4 分支。

状态机模型只对 16 字节实验数据计算 CRC，用于简化演示。最终 P4 应按小组的 UDP 或 TCP 方案对实际到达的内层字段重新计算 `observed_crc`，并保证源网关和目的网关使用相同的字段顺序和位宽。

实际提交必须在目的网关 P4 数据面完成裁决；Python 模型不能作为最终裁决程序。
