@echo off
rem Launch CICFlowMeter v3 GUI on Windows.
rem Uses jnetpcap 1.3.0 (jar + 64-bit DLL bundled in jnetpcap\win\jnetpcap-1.3.0) because the
rem jnetpcap 1.4 Windows DLL is missing from this copy. The 1.3.0 jar is placed first on the
rem classpath so it overrides lib\jnetpcap-1.4.1.jar. Requires Npcap (WinPcap-compatible) and JDK 8.
cd /d "%~dp0"
set "JAVA=C:\Users\HOME PC\AppData\Local\Programs\Eclipse Adoptium\jdk-8.0.504.1-hotspot\bin\java.exe"
"%JAVA%" -Djava.library.path=jnetpcap\win\jnetpcap-1.3.0 -cp "jnetpcap\win\jnetpcap-1.3.0\jnetpcap.jar;build\install\CICFlowMeter\lib\*" cic.cs.unb.ca.ifm.App
