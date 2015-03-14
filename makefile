CXX = g++

SDL_LIB = -L/usr/local/lib -lpthread -lsodium -lncurses -Wl,-rpath=/usr/local/lib
SDL_INCLUDE = -I/usr/local/include

CXXFLAGS = -Wall -c -std=c++11 -fmax-errors=1  $(SDL_INCLUDE)
LDFLAGS = $(SDL_LIB)

EXE = test
objects = main.o

$(EXE): $(objects)
	$(CXX) $^ $(LDFLAGS) -o $@

main.o : main.cpp 
	$(CXX) $(CXXFLAGS) $< -o $@

install: $(objects)
	$(CXX) $^ $(LDFLAGS) -o /usr/bin/pbox


clean:
	rm *.o && rm $(EXE)