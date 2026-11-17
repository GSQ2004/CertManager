# CertManager 1.2.0 验证记录

日期：2026-11-17 UTC。实际工程位于 `/workspace/CertManager`，从现有 GitHub 仓库克隆并保留提交历史；开发分支 `feat/guarded-root-ca-uninstall`。没有重新初始化仓库。未提交用户证书、备份、签名密钥或设备敏感日志。

## 本地实际结果

| 项目 | 结果 |
| --- | --- |
| JVM 单元测试 | **64 项通过**：CertificateTests 21、CleanupTests 21、RootFileTests 22；0 失败、0 错误、0 跳过 |
| `testDebugUnitTest lintDebug assembleDebug` | 成功；原生暂存位置调整和最终 Kotlin/CA 属性检查后再次整体执行，`BUILD SUCCESSFUL`，测试/Lint 缓存有效，两个 ABI 原生代码重新编译并打包 |
| Android Lint | 0 错误；依赖更新提示及受限安装目录的 JNI 绝对路径加载警告保留，没有 baseline 或禁用检查 |
| 原生构建 | NDK r27c / CMake 3.22.1，arm64-v8a 与 x86_64 均编译成功；C++ `-Wall -Wextra -Werror` |
| 16 KiB ELF 对齐 | `llvm-readelf` 检查 arm64 库三个 LOAD 段均为 `0x4000`；仅静态检查，不是 16 KiB 设备运行验收 |
| APK | 实际存在，**59,567,502 字节**；1.2.0 / versionCode 3，包名 `com.certmanager.android`，minSdk 29，compile/targetSdk 36 |
| APK SHA-256 | `c83729c7c3c07e57b1910c5fb0850a99af0a7f207587b16d67c5190d38d2a43e`（本地 Debug 产物；Actions 使用自己的 Debug 密钥，哈希不同属正常） |
| APK 签名 | `apksigner verify --verbose` 成功，v2 签名，1 个签名者；调试用途 |
| APK 权限 | 仅 AndroidX 动态接收器签名权限；无网络、广泛存储或跨用户权限 |
| 原生库打包 | APK 含 `lib/arm64-v8a/libcertguard.so`、`lib/x86_64/libcertguard.so`；未包含测试 CA 资源 |
| GitHub Actions 语法 | actionlint 1.7.7 通过，0 问题 |
| Git 变更格式 | `git diff --check` 通过；保留已有 1.1.0 下载产物，未提交新 APK |
| 真机安装 / 启动 / 仪器化测试 | **未执行**；云端没有建立可用 ADB 设备会话，不能据静态 APK 校验宣称设备启动成功 |

工具链：完整 Temurin JDK 17.0.21、Gradle Wrapper 8.13、AGP 8.11.1、Kotlin 2.1.20、SDK / build-tools 36、NDK 27.2.12479018、CMake 3.22.1。下载 SDK 归档已对照官方仓库元数据校验。环境专用 SDK 路径、Gradle 缓存和代理信任配置均在仓库外或未提交的 local.properties 中。

执行命令：

```sh
./gradlew --offline --no-daemon --console=plain testDebugUnitTest lintDebug assembleDebug
apksigner verify --verbose app/build/outputs/apk/debug/app-debug.apk
aapt dump badging app/build/outputs/apk/debug/app-debug.apk
sha256sum app/build/outputs/apk/debug/app-debug.apk
actionlint .github/workflows/android.yml
git diff --check
```

离线参数只用于已完成依赖下载的本地复核；Actions 正常联网构建。第一次 Lint 发现详情页直接访问 StateFlow.value，已改为使用收集后的状态传参，并通过后续 Lint；没有忽略错误。Android 工具无法写只读 HOME 下的分析配置时有 metrics 提示，不影响构建结果。

## 新增测试的实际边界

RootFileTests 用可注入的 `RootCertificateFiles` 和进程工厂测试：

- PEM 原始字节与 DER 指纹区别、文件元数据往返、v1 备份兼容、v2 完整性。
- 路径穿越、非法名、未知用户、跨用户错配、系统/模块来源拒绝。
- 符号链接、非普通文件和额外挂载边界错误的故障传播（**JVM 失败注入，不是 Android syscall 实测**）。
- Root 拒绝及超时，进程销毁、只读状态、结果记录，无实际启动 su。
- 无匹配备份、inode 变化、移动失败 / EXDEV、损坏备份、移出后重新出现时失败保留。
- 恢复目标存在、确认后出现目标或重复、UID/GID/权限/SELinux/原子发布失败、确认一次有效、原用户核实。
- 文件移出、重启复查、用户确认警告消失的独立状态及持久化。

CleanupTests 另外验证 Root 批量部分失败、同指纹多文件逐张操作后部分失败的移出计数与备份保留。保留原有解析、SHA-256、命令校验、来源分类、重复、覆盖未知、取消、Root 撤销、备份/检查点失败及重现复查测试。

没有在 JVM 测试中修改真实 CA；测试证书是仓库已有公开 fixture，未包含私钥。**原生 syscall 的符号链接/竞态/SELinux 行为、root app_process 类加载与 JNI 命名空间兼容性，仍需要真机测试。**

## 必须区分的三类证据

1. **用户此前真机验证**：Android 17 / API 37 + HyperOS + KernelSU，手动移出传统用户 CA 后重启，警告消失。这是用户报告的手动案例，没有把其目标文件名或历史指纹加入应用逻辑。
2. **应用自动化验证**：本次 64 项 JVM 测试、两 ABI 原生交叉编译、Lint、APK 签名/元数据/库打包、工作流静态检查通过。
3. **应用待真机验证**：所有 Root 文件级卸载/恢复、root JNI 启动、挂载拒绝、权限/SELinux、Android 13–17 / HyperOS、多用户/工作资料、掉电/竞态与重启后警告消失，均未由本云端环境验证。

建议先在测试设备对可信测试 CA 验收：拒绝/允许/撤销 Root，核对字节与完整元数据备份，单张移出及取消，批量部分失败，元数据恢复，重复/覆盖拒绝，重启后再出现与模块诊断。系统 CA 和 APEX 必须保持只读；不自动重启。若无法确认读取覆盖、目录身份或上下文，保持失败/未确认，禁止虚报系统警告已消失。

GitHub 运行和 Artifact 以本次 PR 的 Checks 为准。本地 APK 不是远程 CI 产物，不能复用本地哈希宣称 Actions 同一签名。
