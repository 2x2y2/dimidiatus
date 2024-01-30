all:
	nasm -g -f elf64 dimidiatus.asm -o dimidiatus.o
	ld dimidiatus.o -o dimidiatus
	rm dimidiatus.o
	gcc hello_world.c -o hello_world
