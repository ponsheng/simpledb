exe=simpledb

all: $(exe) test-file elfdemo

src=src/simpledb.c src/elftool.c
src2=src/elfdemo.c src/elftool.c

$(exe): $(src)
	gcc $^ -o $@ -Iinclude -lelf
elfdemo: $(src2)
	gcc $^ -o $@ -Iinclude -lelf

test-file:
	make -C test

clean:
	rm -f $(exe) elfdemo
	make clean -C test
