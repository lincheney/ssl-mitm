LIBRARY=ssl-mitm.so

all: ${LIBRARY}

${LIBRARY}: ssl-mitm.c
	gcc -fPIC -shared -o $@ $<
