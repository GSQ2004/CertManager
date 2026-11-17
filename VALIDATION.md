# CertManager 1.1.0 开发与验收记录

日期：2026-11-17 UTC。本记录描述云端构建与验收阶段：当时未创建远程仓库、未配置 CI、未推送或发布 APK，也未上传设备证书/私钥/备份/设备数据。后续按项目所有者授权同步源码至 GitHub；该同步不改变下述构建验证结果，也不发布 APK 或设备数据。

## 实际验证

| 项目 | 结果 |
| --- | --- |
| `./gradlew testDebugUnitTest` | 成功；共 **40 项**（原 21 项 + 清理新增 19 项），0 失败、0 错误、0 跳过。 |
| `./gradlew assembleDebug` | 成功，APK 已检查实际存在。 |
| `./gradlew lintDebug` | 成功；0 错误、4 条依赖版本更新提示，没有屏蔽检查或 baseline。 |
| APK 签名 | apksigner 验证通过，v2 签名，debug 测试用途。 |
| APK 元数据 | `com.certmanager.android`，versionName **1.1.0**，versionCode **2**，minSdk 29、targetSdk / compileSdk 36。 |
| APK 权限 | 无网络、广泛存储或跨用户权限；仅 AndroidX 自身动态接收器签名权限。 |
| 设备验证 | 云端无 Android 真机或模拟器；未测试实际 su / DPM / HyperOS / UI / 重启行为。 |

本环境复用 JDK 21、Android SDK 36、Build Tools 35.0.0、Gradle 8.13。最终合并执行 `./gradlew --offline testDebugUnitTest assembleDebug lintDebug --console=plain`，使用缓存依赖，无上传。附加了本机 JAVA_HOME、GRADLE_USER_HOME 和系统 Java trustStore 环境参数。Gradle 文件锁通信在常规沙箱受限，使用允许的沙箱外命令执行；没有关闭 TLS 校验。日志、JUnit XML、Lint、APK 元数据和签名报告位于 `validation/`。

## 新增功能

- 首页“CA 安全警告处理”和用户页“清理全部用户 CA”。展示数量、用户分布、全部来源、可安全自动卸载数、无法自动卸载数、备份状态、清理进度、逐项结果及重启后复查入口。
- 扫描当前资料 AndroidCAStore、具备所有者权限时的 DPM/KeyChain CA 查询、其他用户和工作资料的已知存储位置，并记录读取覆盖情况。用户 CA、系统 CA、模块 CA 分离；`cacerts-removed` 仅诊断。
- Root 模块白名单目录中的证书副本、固定启动脚本的关键词和 disable/remove 标记只读诊断，不执行脚本、不改模块，不将候选副本宣称为实际注入。
- 批量第一次范围确认后重新扫描，逐来源保存原始证书并回读校验全部 SHA-256；全部成功才生成一次性票据。第二次确认包含影响勾选；执行前再次全量核验，之后逐项卸载/跳过/记录失败。
- 清理前和每项操作后原子保存检查点；保存失败即停止。重新打开或重启复查不会重放删除。检查目标残留、重复位置、再出现的目标指纹、模块及新增系统来源匹配。
- 单张卸载返回后增加全来源残留检查；源目录或目标文件不可读时不计为已验证移除。最后扫描发现残留或覆盖丢失会撤销本轮成功判定。
- 每次 Root 读命令执行前检查已请求授权、路径白名单及命令实际 UID 0。所有修改仍仅走经确认的公开 DPM CA 卸载 API。

## 19 项新增离线测试

来源分类（用户/资料/系统/模块/禁用记录）、模块命令及路径约束、API 镜像去重与重复位置、读取失败保持未知、全来源批量备份原始字节、首次/后续备份失败、取消、最后一份备份损坏、目标变化阻止首次卸载、提交前授权撤销、部分成功和跳过、卸载后覆盖丢失、跨进程/重启复查和再出现目标、启动标记未知、系统/模块禁止作为目标、中途 Root 撤销、清理中重新出现、持久检查点失败。

所有测试只使用专门生成的公开测试证书、TemporaryFolder 与伪凭据网关；不执行 su、不读取或修改设备证书，测试私钥不在源码中。

## 能力限制与尚未完成的真机验证

**普通 Root 不提供通用、稳定的 KeyChain 卸载接口。**只有本应用已是当前资料的 device/profile owner，且凭据 API 中可见目标时，本版才能通过公开 DPM API 自动卸载。普通安装通常自动可卸载数为 0；会备份并逐项跳过，提供对应资料的系统设置入口进行真正卸载。没有直接删证书文件、清空目录、修改数据库、系统分区/APEX、SELinux、Hook 或隐藏警告。

不保证穷尽发现自定义模块外置路径、modules_update、临时挂载、厂商私有存储或锁定资料。禁用标记仅诊断，不删除；模块不自动移除。相同指纹位置可能是 API 别名/挂载/跨资料副本，不自动增加删除范围。系统启动计数不可读取时，不确认已重启。扫描零用户 CA 不代表 HyperOS 警告消失；应继续检查工作资料、第二空间、设备管理策略和未覆盖来源。

仍需 HyperOS / Android 13–16 真机验证三种 Root 管理器授权与 SELinux 下读取、多用户/工作资料锁定与解锁、凭据服务与设置入口、预先合法 provision 的 DPM 卸载分支、部分失败与残留、Root 模块注入线索及重启前后对比、旋转和进程回收、UI 和导入恢复原有流程。

## 交付文件

- 原始 APK：`/workspace/CertManager/app/build/outputs/apk/debug/app-debug.apk`
- APK 副本：`/workspace/library-files/CertManager-debug.apk`
- 实际大小：**58,748,968 字节**（56.03 MiB）
- APK SHA-256：`af1cab456da9457e8d9d3eeeb5bd87495c4b84ad255595d32e492ea5b6056d93`
- 完整源码：`/workspace/library-files/CertManager-source.zip`

源码 ZIP 包含 Wrapper、代码、资源、公开测试证书、40 项测试及验收记录；排除 SDK、缓存、构建目录、local.properties 和签名私钥。两个交付文件为真实云端工作区文件，没有发布外网下载地址；支持的客户端可打开并另存为。
