/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/proxy/vless_parser.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>

namespace MTP::Proxy {

bool VlessParams::valid() const {
	return !server.isEmpty()
		&& port != 0
		&& !uuid.isEmpty();
}

std::optional<VlessParams> ParseVlessUrl(const QString &input) {
	const auto trimmed = input.trimmed();
	if (!trimmed.startsWith(u"vless://"_q, Qt::CaseInsensitive)) {
		return std::nullopt;
	}

	const auto url = QUrl(trimmed, QUrl::StrictMode);
	if (!url.isValid() || url.userName().isEmpty() || url.host().isEmpty()) {
		return std::nullopt;
	}

	VlessParams p;
	p.uuid = url.userName();
	p.server = url.host();
	const int port = url.port();
	if (port <= 0 || port > 65535) {
		return std::nullopt;
	}
	p.port = quint16(port);
	p.name = url.fragment(QUrl::FullyDecoded);

	const auto q = QUrlQuery(url);
	const auto get = [&](const QString &key) {
		return q.queryItemValue(key, QUrl::FullyDecoded);
	};

	p.transport = get(u"type"_q).toLower();
	if (p.transport.isEmpty()) p.transport = u"tcp"_q;

	p.security = get(u"security"_q).toLower();
	if (p.security.isEmpty()) p.security = u"none"_q;

	p.sni = get(u"sni"_q);
	if (p.sni.isEmpty()) p.sni = get(u"peer"_q);

	const auto alpnRaw = get(u"alpn"_q);
	if (!alpnRaw.isEmpty()) {
		p.alpn = alpnRaw.split(u',', Qt::SkipEmptyParts);
		for (auto &a : p.alpn) a = a.trimmed();
	}

	p.fingerprint = get(u"fp"_q);
	p.flow        = get(u"flow"_q);
	p.publicKey   = get(u"pbk"_q);
	p.shortId     = get(u"sid"_q);
	p.path        = get(u"path"_q);
	p.host        = get(u"host"_q);
	p.serviceName = get(u"serviceName"_q);
	p.headerType  = get(u"headerType"_q).toLower();

	const auto allow = get(u"allowInsecure"_q);
	p.allowInsecure = (allow == u"1"_q || allow.compare(u"true"_q, Qt::CaseInsensitive) == 0);

	return p.valid() ? std::optional<VlessParams>(std::move(p)) : std::nullopt;
}

QString BuildSingboxOutboundJson(const VlessParams &p) {
	QJsonObject o;
	o[u"type"_q]        = u"vless"_q;
	o[u"tag"_q]         = u"proxy"_q;
	o[u"server"_q]      = p.server;
	o[u"server_port"_q] = int(p.port);
	o[u"uuid"_q]        = p.uuid;
	if (!p.flow.isEmpty()) {
		o[u"flow"_q] = p.flow;
	}

	// TLS / Reality
	if (p.security == u"tls"_q || p.security == u"reality"_q) {
		QJsonObject tls;
		tls[u"enabled"_q] = true;
		if (!p.sni.isEmpty()) {
			tls[u"server_name"_q] = p.sni;
		} else {
			tls[u"server_name"_q] = p.server;
		}
		if (p.allowInsecure) {
			tls[u"insecure"_q] = true;
		}
		if (!p.alpn.isEmpty()) {
			QJsonArray alpnArr;
			for (const auto &a : p.alpn) alpnArr.append(a);
			tls[u"alpn"_q] = alpnArr;
		}
		if (!p.fingerprint.isEmpty()) {
			QJsonObject utls;
			utls[u"enabled"_q] = true;
			utls[u"fingerprint"_q] = p.fingerprint;
			tls[u"utls"_q] = utls;
		}
		if (p.security == u"reality"_q && !p.publicKey.isEmpty()) {
			QJsonObject reality;
			reality[u"enabled"_q] = true;
			reality[u"public_key"_q] = p.publicKey;
			if (!p.shortId.isEmpty()) {
				reality[u"short_id"_q] = p.shortId;
			}
			tls[u"reality"_q] = reality;
		}
		o[u"tls"_q] = tls;
	}

	// Transport (omit for plain TCP without http headerType)
	const auto t = p.transport;
	const auto isHttpOverTcp = (t == u"tcp"_q && p.headerType == u"http"_q);
	if (t != u"tcp"_q || isHttpOverTcp) {
		QJsonObject tr;
		if (t == u"ws"_q) {
			tr[u"type"_q] = u"ws"_q;
			if (!p.path.isEmpty()) tr[u"path"_q] = p.path;
			if (!p.host.isEmpty()) {
				QJsonObject h; h[u"Host"_q] = p.host;
				tr[u"headers"_q] = h;
			}
		} else if (t == u"httpupgrade"_q) {
			tr[u"type"_q] = u"httpupgrade"_q;
			if (!p.path.isEmpty()) tr[u"path"_q] = p.path;
			if (!p.host.isEmpty()) tr[u"host"_q] = p.host;
		} else if (t == u"grpc"_q) {
			tr[u"type"_q] = u"grpc"_q;
			if (!p.serviceName.isEmpty()) {
				tr[u"service_name"_q] = p.serviceName;
			}
		} else if (t == u"http"_q || isHttpOverTcp) {
			tr[u"type"_q] = u"http"_q;
			if (!p.path.isEmpty()) {
				QJsonArray paths; paths.append(p.path);
				tr[u"path"_q] = paths;
			}
			if (!p.host.isEmpty()) {
				QJsonArray hosts; hosts.append(p.host);
				tr[u"host"_q] = hosts;
			}
		} else {
			tr[u"type"_q] = t;
		}
		o[u"transport"_q] = tr;
	}

	return QString::fromUtf8(
		QJsonDocument(o).toJson(QJsonDocument::Compact));
}

} // namespace MTP::Proxy
