CC = gcc
CFLAGS = -Wall -Wextra
EXECUTABLE = main.exe

all: $(EXECUTABLE)

$(EXECUTABLE): main.c
	$(CC) $(CFLAGS) $< -o $@

run: $(EXECUTABLE)
	./$(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE)

.PHONY: all run clean