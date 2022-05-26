Obj_OS := $(patsubst %.cpp, %.o, $(wildcard OS/*.cpp))
Obj_Socket := $(patsubst %.cpp, %.o, $(wildcard Socket/*.cpp))
Obj_Session := $(patsubst %.cpp, %.o, $(wildcard Session/*.cpp))
Obj_Main := $(patsubst %.cpp, %.o, $(wildcard Main/*.cpp))

OBJS := $(Obj_Main) $(Obj_OS) $(Obj_Socket) $(Obj_Session)

INC :=-I./Main -I./OS/ -I./Socket -I./Session
Libs := -lpthread -ljson -lEChainLKAPI -L./ -L/lib64/ 

CFLAGS := -c -g -D_LINUX_
CC := g++
COPY  = cp
EXECUTABLE = EChainServer

all : $(EXECUTABLE)

$(EXECUTABLE): $(OBJS) 
	$(CC) -g $^ -o $@ -L./ -L/lib -L/usr/lib $(Libs) $(INC) 
	$(COPY) $(EXECUTABLE) ./bin/
	
$(OBJS) : %.o : %.cpp
	$(CC) $(CFLAGS) $< $(INC) -o $@ 
	
clean:
	rm -rf $(OBJS) $(EXECUTABLE)

