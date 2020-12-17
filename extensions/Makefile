CFLAGS = -O2 -Wall
NAME = libxt_detectTls
LIBNAME = ${NAME}.so 
all: ${LIBNAME}

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean:
	rm -f ${NAME}.o ${LIBNAME}
