# AgentLens v0.1

当前实现是基于 `docs/agentlens/ARCHITECTURE.md` 的 VS2022 工程骨架和首个可编译闭环。

## 已实现

- `AgentLensKernel.sys`
  - 控制设备 `\Device\AgentLensControl`
- 事件 ring
- 进程/线程/镜像/注册表/对象监控
- 文件 Minifilter 监控
- 策略加载接口
- 文件/注册表 Open/Create 控制策略
- Event Ring 共享内存映射
- `AgentLensService.exe`
  - 控制通道客户端
  - 事件读取和打印
  - 策略加载接口
- `AgentLensAgent.dll`
  - 空骨架，后续接入用户态辅助采集
- `AgentLensTools.exe`
  - 版本、统计、订阅控制工具
- `AgentLensKernel.sys` 已合并 WFP ALE callout
  - Connect / Recv Accept V4/V6

## 尚未实现

- 命令行上下文增强、ETW、签名验证、安装器。

## 构建

```cmd
msbuild AgentLens.sln /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

或执行：

```cmd
build.cmd Debug
```

## 运行

1. 在测试环境加载 `AgentLensKernel.sys`。
2. 以管理员运行：

```cmd
AgentLensService.exe --console
```

3. 查看进程/线程/镜像/文件/注册表事件。

## 安装 / 签名

见 `installer/README.md`。

控制工具：

```cmd
AgentLensTools.exe --version
AgentLensTools.exe --stats
AgentLensTools.exe --policy <binary-policy-file>
AgentLensTools.exe --clear-policy
AgentLensTools.exe --driver-stop
AgentLensTools.exe --driver-start
AgentLensTools.exe --driver-restart
```
