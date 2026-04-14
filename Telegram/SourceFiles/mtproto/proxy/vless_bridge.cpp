/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/vless_bridge.h"

#include "mtproto/proxy/vless_parser.h"
#include "logs.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QLibrary>
#include <QtCore/QMutexLocker>

namespace MTP::Proxy {
namespace {

constexpr auto kDllName = "singbox";

[[nodiscard]] QString DllSearchPath() {
	return QDir(QCoreApplication::applicationDirPath())
		.absoluteFilePath(QStringLiteral("singbox"));
}

} // namespace

VlessBridge &VlessBridge::instance() {
	static VlessBridge v;
	return v;
}

VlessBridge::VlessBridge() = default;

VlessBridge::~VlessBridge() {
	shutdownAll();
}

bool VlessBridge::ensureLoaded() {
	if (_lib && _lib->isLoaded()) {
		return true;
	}
	_lib = std::make_unique<QLibrary>(DllSearchPath());
	if (!_lib->load()) {
		LOG(("VLESS: failed to load singbox dll from %1: %2"
			).arg(DllSearchPath(), _lib->errorString()));
		_lib.reset();
		return false;
	}
	_start      = (int  (*)(const char*)) _lib->resolve("SingboxStart");
	_stop       = (int  (*)(int))         _lib->resolve("SingboxStop");
	_getPort    = (int  (*)(int))         _lib->resolve("SingboxGetPort");
	_getUser    = (char*(*)(int))         _lib->resolve("SingboxGetUser");
	_getPass    = (char*(*)(int))         _lib->resolve("SingboxGetPass");
	_lastError  = (char*(*)())            _lib->resolve("SingboxLastError");
	_freeString = (void (*)(char*))       _lib->resolve("SingboxFreeString");
	if (!_start || !_stop || !_getPort || !_getUser
			|| !_getPass || !_lastError || !_freeString) {
		LOG(("VLESS: singbox dll missing exports"));
		_lib->unload();
		_lib.reset();
		return false;
	}
	return true;
}

ProxyData VlessBridge::ensureRunning(const ProxyData &vlessProxy) {
	Expects(vlessProxy.type == ProxyData::Type::Vless);

	const auto &rawUrl = vlessProxy.host; // Vless stores URL in host
	QMutexLocker lock(&_mu);

	if (const auto it = _running.find(rawUrl); it != _running.end()) {
		ProxyData out;
		out.type = ProxyData::Type::Socks5;
		out.host = QStringLiteral("127.0.0.1");
		out.port = it->second.port;
		out.user = it->second.user;
		out.password = it->second.pass;
		return out;
	}

	if (!ensureLoaded()) {
		return {};
	}

	const auto parsed = ParseVlessUrl(rawUrl);
	if (!parsed || !parsed->valid()) {
		LOG(("VLESS: cannot parse URL"));
		return {};
	}

	const auto outboundJson = BuildSingboxOutboundJson(*parsed);
	const auto bytes = outboundJson.toUtf8();
	const int id = _start(bytes.constData());
	if (id <= 0) {
		if (_lastError && _freeString) {
			if (char *err = _lastError()) {
				LOG(("VLESS: sing-box start failed: %1"
					).arg(QString::fromUtf8(err)));
				_freeString(err);
			}
		}
		return {};
	}

	Running r;
	r.id = id;
	r.port = quint16(_getPort(id));
	char *u = _getUser(id);
	char *p = _getPass(id);
	r.user = QString::fromUtf8(u ? u : "");
	r.pass = QString::fromUtf8(p ? p : "");
	if (u) _freeString(u);
	if (p) _freeString(p);

	_running.emplace(rawUrl, r);

	LOG(("VLESS: sidecar up for '%1' on 127.0.0.1:%2"
		).arg(parsed->name.isEmpty() ? parsed->server : parsed->name
		).arg(r.port));

	ProxyData out;
	out.type = ProxyData::Type::Socks5;
	out.host = QStringLiteral("127.0.0.1");
	out.port = r.port;
	out.user = r.user;
	out.password = r.pass;
	return out;
}

void VlessBridge::stop(const QString &rawUrl) {
	QMutexLocker lock(&_mu);
	const auto it = _running.find(rawUrl);
	if (it == _running.end()) return;
	if (_stop) _stop(it->second.id);
	_running.erase(it);
}

void VlessBridge::shutdownAll() {
	QMutexLocker lock(&_mu);
	if (_stop) {
		for (const auto &[url, r] : _running) {
			_stop(r.id);
		}
	}
	_running.clear();
	// Do NOT unload the DLL — Go runtime doesn't survive DLL unload cleanly.
	// The DLL will be released when the process exits.
}

} // namespace MTP::Proxy
