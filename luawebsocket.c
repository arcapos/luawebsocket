/*
 * Copyright (c) 2014 - 2016 by Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Micro Systems Marc Balmer nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* WebSocket for Lua */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "luawebsocket.h"

#include "websocket.h"

#define BUFSIZE		65535

static int
websocket_accept(lua_State *L)
{
	WEBSOCKET *websock;
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	int socket, ret;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);
	socket = accept(websock->socket, (struct sockaddr *)&addr, &len);

	if (socket == -1) {
		return luaL_error(L, "error accepting connection");
	} else {
		WEBSOCKET *acc;

		acc = lua_newuserdata(L, sizeof(WEBSOCKET));
		memset(acc, 0, sizeof(WEBSOCKET));
		luaL_getmetatable(L, WEBSOCKET_METATABLE);
		lua_setmetatable(L, -2);

		acc->socket = socket;

		if (websock->ctx != NULL) {
			if ((acc->ssl = SSL_new(websock->ctx)) == NULL)
				return luaL_error(L, "error creating SSL "
				    "context");

			if (!SSL_set_fd(acc->ssl, socket))
				return luaL_error(L, "can't set SSL socket");
			if ((ret = SSL_accept(acc->ssl)) <= 0)
				return luaL_error(L, "can't accept SSL "
				    "connection: SSL error code %d",
				    SSL_get_error(acc->ssl, ret));
		}
	}
	return 1;
}

static int
websocket_bind(lua_State *L)
{
	struct addrinfo hints, *res, *res0;
	int fd, error, optval;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	const char *port, *host, *cert;
	WEBSOCKET *websock;

	cert = NULL;

	switch (lua_gettop(L)) {
	case 3:
		cert = luaL_checkstring(L, 3);
	default:
		host = luaL_checkstring(L, 1);
		port = luaL_checkstring(L, 2);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if ((error = getaddrinfo(host, port, &hints, &res0)))
		return luaL_error(L, "%s: %s\n", host, gai_strerror(error));
	fd = -1;
	for (res = res0; res; res = res->ai_next) {
		error = getnameinfo(res->ai_addr, res->ai_addrlen, hbuf,
		    sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST |
		    NI_NUMERICSERV);
		if (error)
			continue;
		fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (fd < 0)
			continue;
		optval = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval,
		    sizeof optval);
		if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}

	if (fd < 0)
		return luaL_error(L, "connection error");

	if (listen(fd, lua_gettop(L) > 1 ? luaL_checkinteger(L, 2) : 32))
		return luaL_error(L, "listen error");

	/* XXX seed_prng(); */
	websock = lua_newuserdata(L, sizeof(WEBSOCKET));
	memset(websock, 0, sizeof(WEBSOCKET));

	websock->socket = fd;

	if (cert != NULL) {
		SSL_library_init();
		SSL_load_error_strings();
		if ((websock->ctx = SSL_CTX_new(SSLv23_method())) == NULL)
			return luaL_error(L, "error creating new SSL context");

		if (SSL_CTX_use_certificate_chain_file(websock->ctx, cert) != 1)
		    	return luaL_error(L, "error loading certificate");
		if (SSL_CTX_use_PrivateKey_file(websock->ctx, cert,
		    SSL_FILETYPE_PEM) != 1)
			return luaL_error(L, "error loading private key");
	}
	luaL_getmetatable(L, WEBSOCKET_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static int
check_resources(lua_State *L, char *resource)
{
	if (lua_isstring(L, 2) && !strcmp(resource, luaL_checkstring(L, 2)))
		return 1;

	if (lua_istable(L, 2)) {
		lua_pushnil(L);
		while (lua_next(L, 2) != 0) {
			if (!strcmp(resource, luaL_checkstring(L, -1)))
				return 1;

			lua_pop(L, 1);
		}
	}

	return 0;
}

static int
websocket_handshake(lua_State *L)
{
	struct handshake hs;
	size_t nread;
	WEBSOCKET *websock;
	char *buf;

	nullHandshake(&hs);
	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);

	buf = malloc(BUFSIZE);
	if (websock->ssl)
		nread = SSL_read(websock->ssl, buf, BUFSIZE);
	else
		nread = recv(websock->socket, buf, BUFSIZE, 0);
	buf[nread] = '\0';

	if (wsParseHandshake((unsigned char *)buf, nread, &hs) ==
	    WS_OPENING_FRAME) {
		if (check_resources(L, hs.resource)) {
			wsGetHandshakeAnswer(&hs, (unsigned char *)buf, &nread);
			lua_pushstring(L, hs.resource);
			freeHandshake(&hs);
			if (websock->ssl)
				SSL_write(websock->ssl, buf, nread);
			else
				send(websock->socket, buf, nread, 0);
			buf[nread] = '\0';
		} else {
			nread = sprintf(buf, "HTTP/1.1 404 Not Found\r\n\r\n");
			if (websock->ssl)
				SSL_write(websock->ssl, buf, nread);
			else
				send(websock->socket, buf, nread, 0);
			lua_pushnil(L);
		}
	} else {
		nread = sprintf(buf,
			"HTTP/1.1 400 Bad Request\r\n"
			"%s%s\r\n\r\n",
			versionField,
			version);
		if (websock->ssl)
			SSL_write(websock->ssl, buf, nread);
		else
			send(websock->socket, buf, nread, 0);
		lua_pushnil(L);
	}
	free(buf);
	return 1;
}

static int
websocket_recv(lua_State *L)
{
	WEBSOCKET *websock;
	char *buf;
	unsigned char *data;
	size_t nread, len, datasize;
	int type;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);

	buf = malloc(BUFSIZE);

	nread = len = 0;
	type = WS_INCOMPLETE_FRAME;
	do {
		if (websock->ssl)
			nread = SSL_read(websock->ssl, buf + len,
			    BUFSIZE - len);
		else
			nread = recv(websock->socket, buf + len,
			    BUFSIZE - len, 0);
		if (nread <= 0) {
			lua_pushnil(L);
			type = WS_EMPTY_FRAME;
		} else {
			len += nread;
			type = wsParseInputFrame((unsigned char *)buf, len,
			    &data, &datasize);
		}
		switch (type) {
		case WS_CLOSING_FRAME:
			wsMakeFrame(NULL, 0, (unsigned char *)buf, &datasize,
			    WS_CLOSING_FRAME);
			if (websock->ssl) {
				SSL_write(websock->ssl, buf, datasize);
				SSL_shutdown(websock->ssl);
				SSL_free(websock->ssl);
				websock->ssl = NULL;
			} else {
				send(websock->socket, buf, datasize, 0);
				close(websock->socket);
				websock->socket = -1;
			}
			lua_pushnil(L);
			break;
		case WS_PING_FRAME:
			wsMakeFrame(NULL, 0, (unsigned char *)buf, &datasize,
			    WS_PONG_FRAME);
			if (websock->ssl)
				SSL_write(websock->ssl, buf, datasize);
			else
				send(websock->socket, buf, datasize, 0);
			len = 0;
			type = WS_INCOMPLETE_FRAME;
			break;
		case WS_TEXT_FRAME:
			lua_pushlstring(L, (const char *)data, datasize);
			break;
		case WS_INCOMPLETE_FRAME:
			break;
		default:
			lua_pushnil(L);
		}
	} while (type == WS_INCOMPLETE_FRAME);
	free(buf);
	return 1;
}

static int
websocket_send(lua_State *L)
{
	char *buf;
	const char *data;
	size_t datasize, framesize;
	WEBSOCKET *websock;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);
	buf = malloc(BUFSIZE);

	data = luaL_checklstring(L, 2, &datasize);
	wsMakeFrame((const uint8_t *)data, datasize, (unsigned char *)buf,
	    &framesize, WS_TEXT_FRAME);
	if (websock->ssl)
		SSL_write(websock->ssl, buf, framesize);
	else
		send(websock->socket, buf, framesize, 0);
	free(buf);
	return 0;
}

static int
websocket_socket(lua_State *L)
{
	WEBSOCKET *websock;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);
	lua_pushinteger(L, websock->socket);
	return 1;
}

static int
websocket_close(lua_State *L)
{
	WEBSOCKET *websock;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);
	if (websock->ssl != NULL) {
		SSL_set_shutdown(websock->ssl,
		    SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		SSL_free(websock->ssl);
		websock->ssl = NULL;
	} else if (websock->socket != -1) {
		close(websock->socket);
		websock->socket = -1;
	}
	if (websock->ctx != NULL) {
		SSL_CTX_free(websock->ctx);
		websock->ctx = NULL;
	}
	return 0;
}

static int
websocket_shutdown(lua_State *L)
{
	WEBSOCKET *websock;

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);
	if (websock->ssl != NULL) {
		SSL_shutdown(websock->ssl);
		SSL_free(websock->ssl);
		websock->ssl = NULL;
	} else if (websock->socket != -1) {
		close(websock->socket);
		websock->socket = -1;
	}
	if (websock->ctx != NULL) {
		SSL_CTX_free(websock->ctx);
		websock->ctx = NULL;
	}
	return 0;
}

static int
websocket_select(lua_State *L) {
	WEBSOCKET *websock;
	fd_set readfds, writefds;
	int ret, timeout, rtop, wtop, max_fd;
	struct timeval tv;

	FD_ZERO(&readfds); FD_ZERO(&writefds);

	websock = luaL_checkudata(L, 1, WEBSOCKET_METATABLE);

	FD_SET(websock->socket, &readfds); FD_SET(websock->socket, &writefds);
	max_fd = websock->socket;

	if (lua_istable(L, 2)) {
		lua_pushnil(L);
		while (lua_next(L, 2) != 0) {
			if (lua_isnumber(L, -1)) {
				int fd = (int) lua_tonumber(L, -1);
				if (fd > 0)
					FD_SET(fd, &readfds);
				if (fd > max_fd)
					max_fd = fd;
			}
			lua_pop(L, 1);
		}
	}

	if (lua_istable(L, 3)) {
		lua_pushnil(L);
		while (lua_next(L, 3) != 0) {
			if (lua_isnumber(L, -1)) {
				int fd = (int) lua_tonumber(L, -1);
				if (fd > 0)
					FD_SET(fd, &writefds);
				if (fd > max_fd)
					max_fd = fd;
			}
			lua_pop(L, 1);
		}
	}

	if (!lua_isnil(L, 4) && lua_isnumber(L, 4))
		timeout = (int) lua_tonumber(L, 4);
	else
		timeout = -1;

	tv.tv_sec = (int) lua_tonumber(L, 4);
	tv.tv_usec = 0;

	ret = select(max_fd + 1, &readfds, &writefds, NULL, timeout >= 0 ? &tv : NULL);
	if (ret > 0) {
		if (FD_ISSET(websock->socket, &readfds)) {
			lua_pushinteger(L, websock->socket);
			lua_pushnil(L);
			return 2;
		}

		lua_newtable(L); rtop = lua_gettop(L);
		lua_newtable(L); wtop = lua_gettop(L);

		int fd;
		int ir = 0, iw = 0;
		for (fd = 0; fd < max_fd + 1; fd++) {
			if (FD_ISSET(fd, &readfds)) {
				lua_pushnumber(L, (lua_Number) fd);
				lua_rawseti(L, rtop, ir + 1);
				ir++;
			} else if (FD_ISSET(fd, &writefds)){
				lua_pushnumber(L, (lua_Number) fd);
				lua_rawseti(L, wtop, iw + 1);
				iw++;
			}
		}

		return 2;
	} else if (ret == 0) {
		lua_pushnil(L);
		lua_pushnil(L);
		lua_pushstring(L, "timeout");
		return 3;
	}

	lua_pushnil(L);
	lua_pushnil(L);
	lua_pushstring(L, "select failed");
	return 3;
}

int
luaopen_websocket(lua_State *L)
{
	struct luaL_Reg methods[] = {
		{ "bind",		websocket_bind },
		{ NULL, NULL }
	};
	struct luaL_Reg websocket_methods[] = {
		{ "accept",		websocket_accept },
		{ "handshake",		websocket_handshake },
		{ "close",		websocket_close },
		{ "shutdown",		websocket_shutdown },
		{ "recv", 		websocket_recv},
		{ "send",		websocket_send },
		{ "socket",		websocket_socket },
		{ "select",		websocket_select },
		{ NULL, NULL }
	};
	if (luaL_newmetatable(L, WEBSOCKET_METATABLE)) {
#if LUA_VERSION_NUM >= 502
		luaL_setfuncs(L, websocket_methods, 0);
#else
		luaL_register(L, NULL, websocket_methods);
#endif
		lua_pushliteral(L, "__gc");
		lua_pushcfunction(L, websocket_close);
		lua_settable(L, -3);

		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

#if LUA_VERSION_NUM >= 502
	luaL_newlib(L, methods);
#else
	luaL_register(L, LUA_WEBSOCKETLIBNAME, methods);
#endif

	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2014 by "
	    "micro systems marc balmer");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "WebSocket for Lua");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");
	lua_pushliteral(L, "websocket 1.0.0");
	lua_settable(L, -3);

	return 1;
}
