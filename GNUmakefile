SRCS=		luawebsocket.c websocket.c base64.c
LIB=		websocket

LUAVER=		`lua -v 2>&1 | cut -c 5-7`

CFLAGS+=	-O3 -Wall -fPIC -I/usr/include -I/usr/include/lua${LUAVER} \
		-D_GNU_SOURCE
LDADD+=		-L/usr/lib -lssl -lcrypto

LIBDIR=		/usr/lib/lua/${LUAVER}

${LIB}.so:	${SRCS:.c=.o}
		cc -shared -o ${LIB}.so ${CFLAGS} ${SRCS:.c=.o} ${LDADD}

clean:
		rm -f *.o *.so
install:
	install -d ${DESTDIR}${LIBDIR}
	install ${LIB}.so ${DESTDIR}${LIBDIR}
