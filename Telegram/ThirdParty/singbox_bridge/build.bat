@echo off
setlocal
set PATH=E:\Claude\TDeskop\mingw64\bin;%PATH%
set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64
set CC=gcc

cd /d "%~dp0"

echo === go mod tidy ===
go mod tidy
if errorlevel 1 exit /b 1

echo === building singbox.dll ===
go build -buildmode=c-shared -ldflags="-s -w" -o singbox.dll .
if errorlevel 1 exit /b 1

echo === done ===
dir singbox.dll singbox.h
