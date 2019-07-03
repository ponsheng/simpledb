obj=hello loop

all:  $(obj)

%: %.c
	gcc -no-pie $^ -o $@


clean:
	rm -f $(obj)
