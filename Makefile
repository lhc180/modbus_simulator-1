SRC_SLAVE_SER = mb_rtubuld.c mbser_func.c mbser_slv.c
SRC_MASTER_SER = mb_rtubuld.c mbser_func.c mbser_mstr.c
SRC_SLAVE_TCP = mbtcp_func.c mbtcp_slv.c
SRC_MASTER_TCP = mbtcp_func.c mbtcp_mstr.c
FLAG = -l pthread

all:   mbtcp_mstr 
#CC = gcc
CC = aarch64-linux-gnu-gcc
mbtcp_mstr: $(SRC_MASTER_TCP)
	$(CC) -Wall -g -o $@ ${SRC_MASTER_TCP} ${FLAG}
clean:
	rm -f mbser_slv mbser_mstr mbtcp_mstr mbtcp_slv
	 
