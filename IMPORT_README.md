# 实验二 / 实验三统一开发起点（材料整合，不是已实现答案）

此目录基于用户提供的课程官方 **第二次实验材料/代码/调度开发骨架/** 原样建立，额外引入第三次实验材料的 **验收工具和接口示例**。没有代写 M1–M6，没有更改 `polymorphic.p4`、`mycontroller.py` 或课程自带 `utils/`。第三次实验的示例统计、参考 PASS 日志均是课程示例，不代表你本机通过。

## 主要文件

- `polymorphic.p4`, `mycontroller.py`, `topo/`, `utils/`：实验二原样开发骨架。
- `STUDENT_TODO.md`：M1–M6 任务接口约定。
- `send-poly.py`, `receive-poly.py`：UDP/5000，16 字节测试输入；第二次和第三次材料版本一致。
- `run-poly-tests.py`, `read-counters.py`, `evaluate-counters.py`：实验三参考自动验收脚本；**在实现相应 P4/控制器功能之前不会通过**。
- `reference/experiment2/`：PolyShim 与 multicast P4Runtime 接口示例。
- `reference/experiment3/`：状态机参考、P4 register/counter 声明片段以及测试工具说明。
- `materials/`：官方第二、第三次实验指导、参考结果和最终提交模板。参考结果不可视作实际测试数据。

## Ubuntu 导入与检查

建议保留之前的 `~/class1/.../三模态原始demo`，避免覆盖第一实验 baseline。

在虚拟机中打开 Firefox，从 ChatGPT 会话下载 `p4_lab_class2_class3_starter.zip` 到 `~/Downloads`，然后执行：

```bash
mkdir -p ~/p4-poly-work
unzip -q ~/Downloads/p4_lab_class2_class3_starter.zip -d ~/p4-poly-work
cd ~/p4-poly-work/p4-poly-lab
pwd
ls -l polymorphic.p4 mycontroller.py STUDENT_TODO.md run-poly-tests.py
```

如果项目复制自共享文件夹并有 Windows 换行问题，先检查再修复；不要修改全局 ~/tutorials/utils。

先只进行静态检查和编译（不启动 Mininet）：

```bash
python3 -m py_compile mycontroller.py send-poly.py receive-poly.py \
  run-poly-tests.py read-counters.py evaluate-counters.py
make build
```

如 `p4c` 找不到，可 `source ~/p4setup.bash` 后重试。

## 推荐实施顺序

1. 记录初始 Git commit（课件骨架，不冒充 `class2-multicast`）。
2. 实验二 M1–M2：解析格式与统一字段；编译及原三模态回归。
3. 实验二 M3–M4：序号、CRC32、group 10、多态异构封装；双向路径抓包，真实通过后创建 `class2-multicast` 标签。
4. 实验三 M5–M6：目的网关 P4 数据面 2/3 投票、状态/统计、去重、恢复。
5. 中间交换机可重复故障注入，五场景自动验收及最终报告。

重要：
- 源端 CRC 不是目的端投票依据；目的网关需对实际到达的内层字段算 `observed_crc`。
- 两台中间交换机如果都 XOR 同一 mask，可能相互抵消。故障控制规则要确保针对目标序号和模态的注入只发生一次。
- 前两个一致时允许第二个胜出报文，第三个只作迟到统计；同一模态重复不能算两票。
- 不要把 `adjudication_model.py` 的 Python 状态机当作已完成的数据平面实现。
- 不要为迎合测试改写五场景的预期结果。
- `make` 可能启动 Mininet，`make clean` 会清理生成产物；执行前确认没有在运行的网络实验。
