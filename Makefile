SRC_SLAVE_SER = mb_rtubuld.c mbser_func.c mbser_slv.c
SRC_MASTER_SER = mb_rtubuld.c mbser_func.c mbser_mstr.c
SRC_SLAVE_TCP = mbtcp_func.c mbtcp_slv.c
SRC_MASTER_TCP = mbtcp_func.c mbtcp_mstr.c
FLAG = -l pthread

all: mbser_slv mbser_mstr mbtcp_mstr mbtcp_slv
#CC = gcc
CC = aarch64-linux-gnu-gcc
mbser_mstr: ${SRC_MASTER_SER}
	$(CC) -Wall -o $@ ${SRC_MASTER_SER}
mbser_slv: ${SRC_SLAVE_SER}
	$(CC) -Wall -o $@ ${SRC_SLAVE_SER}
mbtcp_mstr: $(SRC_MASTER_TCP)
	$(CC) -Wall -o $@ ${SRC_MASTER_TCP} ${FLAG}
mbtcp_slv: ${SRC_SLAVE_TCP}
	$(CC) -Wall -o $@ ${SRC_SLAVE_TCP} ${FLAG}
clean:
	rm -f mbser_slv mbser_mstr mbtcp_mstr mbtcp_slv
	 
