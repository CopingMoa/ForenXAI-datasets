# Tools

Only the Windows launchers are tracked in git. The CICFlowMeter source trees, builds, source zips
and the JDK installer stay local (third-party files; see `.gitignore`).

| Folder | Contents |
|---|---|
| `cicflowmeter_v3/` | CICFlowMeter v3 source (GitHub master snapshot), built with Gradle 4.2 + JDK 8 |
| `cicflowmeter_v4/` | CICFlowMeter v4 source (GitHub master snapshot), built with Gradle 4.2 + JDK 8 |
| `installers/` | `CICFlowMeter-v3-source.zip`, `CICFlowMeter-v4-source.zip`, `OpenJDK8U-jdk_x64_windows_hotspot_8u504b01.msi` |

## Requirements
- Windows, [Npcap](https://npcap.com/) in WinPcap-compatible mode
- JDK 8 (Temurin 8u504 used)

## Build (once per version)
```bat
cd cicflowmeter_v4
set JAVA_HOME=<path to JDK 8>
gradlew.bat --no-daemon installDist -x test
```

## Run
| Version | GUI | Command line |
|---|---|---|
| v3 | `cicflowmeter_v3\run_CICFlowMeter_v3.bat` | see note below |
| v4 | `cicflowmeter_v4\run_CICFlowMeter_v4.bat` | `run_CICFlowMeter_v4.bat cmd "<pcap file or folder>" "<output folder>"` |

Both versions read `.pcap` only (not `.pcapng`).

### v3 note: jNetPcap 1.3.0 workaround
The v3 snapshot is missing the Windows `jnetpcap.dll` for jNetPcap 1.4, which makes processing fail
with `UnsatisfiedLinkError`. The launcher therefore puts the bundled jNetPcap **1.3.0** jar + DLL
(`jnetpcap\win\jnetpcap-1.3.0`) first on the classpath. v3's command-line class
(`cic.cs.unb.ca.ifm.CICFlowMeter`, excluded from the Gradle build) was compiled separately into
`build\cli` and run as:

```bat
java -Djava.library.path=jnetpcap\win\jnetpcap-1.3.0 ^
     -cp "build\cli;jnetpcap\win\jnetpcap-1.3.0\jnetpcap.jar;build\install\CICFlowMeter\lib\*" ^
     cic.cs.unb.ca.ifm.CICFlowMeter "<pcap folder>\" "<output folder>\"
```
