#ifndef MBUS_H
#define MBUS_H

#define READCOILSTATUS 			0x01
#define READINPUTSTATUS 		0x02
#define READHOLDINGREGS 		0x03
#define READINPUTREGS 			0x04
#define FORCESIGLEREGS 			0x05
#define PRESETEXCPSTATUS 		0x06
#define FORCEMUILTCOILS			0x15
#define PRESETMUILTREGS			0x16
#define EXCPTIONCODE			0x80
#define EXCPILLGFUNC			0x01
#define EXCPILLGDATAADDR		0x02
#define READCOILSTATUS_EXCP		129
#define READINPUTSTATUS_EXCP	130
#define READHOLDINGREGS_EXCP	131
#define READINPUTREGS_EXCP		132
#define FORCESIGLEREGS_EXCP		133
#define PRESETEXCPSTATUS_EXCP	134

#define FRMLEN 260  /* | 1byte | 1byte | 0~255byte | 2byte | */

struct slv_frm_para {
	unsigned int slvID;
	unsigned int len;
	unsigned char fc;
	unsigned int straddr;
	unsigned int act;			// The status to write (in FC 0x05)
	unsigned int val;			// The value of write (in FC 0x06) 
};

struct mstr_frm_para{
	unsigned int slvID;
	unsigned int len;
	unsigned char fc;
	unsigned int straddr;
	unsigned int act;
};

int analz_query(unsigned char *rx_buf, struct slv_frm_para *sfpara);
int analz_respond(unsigned char *rx_buf, struct mstr_frm_para *mfpara, int rlen);

void build_rtu_frm(unsigned char *dst_buf, unsigned char *src_buf, unsigned char lenth);
int build_query(unsigned char *tx_buf, struct mstr_frm_para *mfpara);
int build_resp_excp(unsigned char slvID, unsigned int fc, unsigned int excp_code, unsigned char *tx_buf);
int build_resp_read_status(unsigned int slvID, unsigned char *tx_buf, unsigned int straddr, unsigned char fc, int len);
int build_resp_read_regs(unsigned int slvID, unsigned char *tx_buf, unsigned int straddr, unsigned char fc, int num_regs);
int build_resp_set_single(unsigned int slvID, unsigned char *tx_buf, unsigned int straddr, unsigned char fc, unsigned int act);

#endif

