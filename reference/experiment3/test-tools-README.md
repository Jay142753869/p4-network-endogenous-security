# 自动验收工具

将本目录 Python 文件复制到实验项目根目录，与 `polymorphic.p4`、`mycontroller.py`、`Makefile` 同级。

接口约定：

- 控制器支持 `--fault corrupt:MODE:SEQ:MASK` 和 `--fault drop:MODE:SEQ`。
- P4 中存在 `good_count`、`bad_count`、`no_majority_count`。
- `send-poly.py` 和 `receive-poly.py` 是材料内的 UDP/5000、固定 16 字节参考实现。如项目选择 TCP，需在保留原测试场景和数量判定的前提下适配收发、Parser、CRC 和 checksum 处理。

从项目根目录执行：

```bash
python3 run-poly-tests.py
```

若当前终端提示找不到 P4 或 BMv2 命令，再执行一次 `source ~/p4setup.bash` 后重试。

如果实现使用不同表名或计数器名，可以修改工具适配接口，但不得删除验收场景或伪造输出。

将计数器转为三模态评价报告：

```bash
python3 read-counters.py | python3 evaluate-counters.py
```

评价只报告 `HEALTHY/SUSPECT/NO_DATA`；三模态版本仍维持 `ALL_THREE_MODES` 调度。
