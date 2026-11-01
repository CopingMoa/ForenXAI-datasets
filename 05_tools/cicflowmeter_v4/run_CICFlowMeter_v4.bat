@echo off
rem Launch CICFlowMeter v4 GUI on Windows (jnetpcap 1.4 DLL bundled). Requires Npcap and JDK 8.
rem Command-line mode instead:  run_CICFlowMeter_v4.bat cmd "<pcap file or folder>" "<output folder>"
cd /d "%~dp0"
set "JAVA=C:\Users\HOME PC\AppData\Local\Programs\Eclipse Adoptium\jdk-8.0.504.1-hotspot\bin\java.exe"
set "OPTS=-Djava.library.path=build\install\CICFlowMeter\lib\native -cp build\install\CICFlowMeter\lib\*"
if /i "%~1"=="cmd" ( "%JAVA%" %OPTS% cic.cs.unb.ca.ifm.Cmd "%~2" "%~3" ) else ( "%JAVA%" %OPTS% cic.cs.unb.ca.ifm.App )
