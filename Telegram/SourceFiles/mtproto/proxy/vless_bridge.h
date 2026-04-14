/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_proxy_data.h"
#include "base/flat_map.h"

#include <QtCore/QMutex>

class QLibrary;

namespace MTP::Proxy {

// Manages lifecycle of the bundled sing-box sidecar (singbox.dll) that
// terminates VLESS outbounds and exposes a local SOCKS5 inbound for
// the rest of the app to tunnel through.
class VlessBridge final {
public:
	static VlessBridge &instance();

	// Returns a resolved ProxyData (type=Socks5, host=127.0.0.1, port/user/pass
	// assigned by sing-box) for the given VLESS proxy. If sidecar isn't already
	// running for this rawUrl, starts it. On failure returns an invalid ProxyData
	// and writes a log line.
	[[nodiscard]] ProxyData ensureRunning(const ProxyData &vlessProxy);

	// Stop a single VLESS instance (by rawUrl). No-op if not running.
	void stop(const QString &rawUrl);

	// Stop all instances and unload the DLL. Call on app shutdown.
	void shutdownAll();

private:
	VlessBridge();
	~VlessBridge();
	VlessBridge(const VlessBridge &) = delete;
	VlessBridge &operator=(const VlessBridge &) = delete;

	bool ensureLoaded();

	struct Running {
		int id = 0;
		quint16 port = 0;
		QString user;
		QString pass;
	};

	QMutex _mu;
	std::unique_ptr<QLibrary> _lib;

	// Function pointers into singbox.dll
	int   (*_start)(const char*) = nullptr;
	int   (*_stop)(int)          = nullptr;
	int   (*_getPort)(int)       = nullptr;
	char* (*_getUser)(int)       = nullptr;
	char* (*_getPass)(int)       = nullptr;
	char* (*_lastError)()        = nullptr;
	void  (*_freeString)(char*)  = nullptr;

	base::flat_map<QString, Running> _running;
};

} // namespace MTP::Proxy
