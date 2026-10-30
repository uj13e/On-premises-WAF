@echo off
chcp 65001 >nul
rem ===== ルール管理ツール 起動(追加ルールの追加・編集・削除) =====
rem WAF本体とは別のプロセスです。127.0.0.1 だけで待ち受けます。
rem 保存すると、稼働中のWAFが数秒以内にルールを入れ替えます(再起動不要)。
cd /d "%~dp0"
set PORT=8099
title WAF ルール管理ツール
echo ルール管理ツールを起動します: http://127.0.0.1:%PORT%
echo 終了するときは、この画面で Ctrl+C を押すか、画面を閉じてください。
echo.
start "" "http://127.0.0.1:%PORT%"
where python >nul 2>nul
if %errorlevel%==0 (
    python src\waf_rules_tool.py --port %PORT%
) else (
    py src\waf_rules_tool.py --port %PORT%
)
echo.
echo ルール管理ツールが停止しました。上のメッセージを確認してください。
pause
