# 项目运行说明

## 1. 团队信息

- 组号：
- 组长：
- 成员名单：
- Git 仓库：

| 成员 | 主要工作 | 个人总结位置 | 贡献比例 |
| --- | --- | --- | ---: |
|  |  |  |  |

## 2. 环境

- 镜像：2026-Aug-01
- 架构：
- 最终 Git commit：

## 3. 项目版本

- 起始版本：
- 最终版本：
- 主要阶段 tag：

## 4. 编译和启动

```bash
make
```

若当前终端需要额外加载 P4 环境，请在此处说明触发条件和实际使用的命令；不要把 `source ~/p4setup.bash` 写成所有终端固定执行的步骤。

控制器命令：

```bash
python3 mycontroller.py
```

## 5. 自动测试

```bash
python3 run-poly-tests.py
```

## 6. 手工测试和计数器

填写无故障、篡改、丢包、无多数和反向场景的命令。

## 7. 已知限制

说明固定 payload、CRC32 的局限以及 register window 等实现限制。

## 8. 清理

```bash
make stop
make clean
```
