#####################################################
##
## Makefile
##
#####################################################
##
## Authors: Kevin Atighehchi <kevin.atighehchi@unicaen.fr>
##          Morgan Barbier <morgan.barbier@ensicaen.fr>
##
## Updated: 2018-06-26
#####################################################
SRCDIR=src
HEADDIR=inc
LIBDIR=obj
BINDIR=bin
DOCDIR=doc

CC=gcc
CFLAGS=-I$(HEADDIR) -g -Wall -pedantic -Os
LDFLAGS=-lssl -lcrypto

# Les différents sources *.c
SRC=$(wildcard $(SRCDIR)/*.c)
# Les objets correspondants à créer
OBJ=$(SRC:$(SRCDIR)/%.c=$(LIBDIR)/%.o)
# Les exécutables à créer
BIN=$(BINDIR)/ID-Blockchain_test


.PHONY: clean superclean ExecuteTest doc

all: $(BIN) ExecuteTest

#Création des exécutables
$(BIN): $(OBJ)
	$(CC) -o $(BIN) $^ $(CFLAGS) $(LDFLAGS)

# Création des différents *.o à partir des *.c
$(LIBDIR)/%.o: $(SRCDIR)/%.c $(HEADDIR)/*.h 
	$(CC) -o $@ -c $< $(CFLAGS)

ExecuteTest:
	./$(BIN)

doc:
	$(MAKE) -C $(DOCDIR)

# Nettoyage
clean:
	rm -f $(SRCDIR)/*~
	rm -f $(HEADDIR)/*~
	rm -f $(LIBDIR)/*.o

# Nettoyage complet
superclean: clean
	rm -f $(BIN)
