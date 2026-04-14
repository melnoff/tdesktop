/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace MTP::Proxy {

struct VlessParams {
	QString server;
	quint16 port = 0;
	QString uuid;
	QString flow;        // "", "xtls-rprx-vision"
	QString security;    // "none" | "tls" | "reality"
	QString sni;
	QStringList alpn;
	QString fingerprint; // chrome, firefox, safari, ios, android, edge, 360, qq, random
	QString publicKey;   // reality pbk
	QString shortId;     // reality sid
	QString transport;   // "tcp" | "ws" | "grpc" | "http" | "httpupgrade"
	QString path;
	QString host;        // http/ws host header
	QString serviceName; // grpc
	QString headerType;  // "none" | "http"
	QString name;        // user-visible label from fragment
	bool allowInsecure = false;

	[[nodiscard]] bool valid() const;
};

[[nodiscard]] std::optional<VlessParams> ParseVlessUrl(const QString &url);
[[nodiscard]] QString BuildSingboxOutboundJson(const VlessParams &p);

} // namespace MTP::Proxy
