#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <iostream>
#include <fstream>
#include <set>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

char* hostname;
char wp[100] = {0};
set<string> set_hp;
set<uint32_t> set_dhost;
int net_mode;
// uint32_t tar_shost = 0;
// uint32_t tar_dhost = 0;

struct ethernet_hdr
{
    u_int8_t ether_dhost[6]; // destination host
    u_int8_t ether_shost[6]; // source host
    u_int16_t ether_type; // type of ethernet
};

struct ipv4_hdr
{
    u_int8_t ver_ihl; //version and IHL
    u_int8_t DSCP_ECN; //DSCP and ECN
    u_int16_t len; // total length
    u_int16_t id; // identification
    u_int16_t flag_frag_offset; // flags and fragment offset
    u_int8_t ttl; // time to live
    u_int8_t protocol; // protocol
    u_int16_t checksum; // header checksum
    uint32_t ip_shost; // source IP address
    uint32_t ip_dhost; // dest IP address
};

struct TCP_hdr
{
    u_int16_t tcp_sport; // source port
    u_int16_t tcp_dport; // dest port
    uint32_t seq_num; // sequence number
    uint32_t ack_num; // acknowledge number
    u_int16_t data_offset_else; // data offset and else things
    u_int16_t window_size; // window size
    u_int16_t checksum; // checksum
    u_int16_t urg_pointer; // urgent pointer
};

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void _strstr(unsigned char* origin, int origin_len, char* find, int find_len) {
	int flag = 0, start_pos = -1;
	for (int num1 = 0; num1 < 100; num1++) { 
		wp[num1] = 0;
	}
	for (int num1 = 0; num1 < origin_len; num1++) {
		for (int num2 = 0; num2 < find_len; num2++) {
			if (num1 + num2 >= origin_len) {
				break;
			}
			if (origin[num1 + num2] != find[num2]) {
				break;
			}
			if (num2 == find_len - 1) {
				flag = 1;
				start_pos = num1 + find_len;
			}
		}
		if (flag == 1){
			break;
		}
	}
	
	if (start_pos != -1){
		int pos = start_pos;
		int num1 = 0;
		while (origin[pos + 1] != ' ' && origin[pos + 1] != '\n' && pos + 1 < origin_len) {
			wp[num1] = origin[pos];
			num1++;
			pos++;
		}
	}
}

int dump_analyze(unsigned char* buf, int size) {
	char str[100] = "Host: www.";
	// strcat(str, hostname);
	uint32_t tar_dhost;
	struct TCP_hdr* tcpp;
	struct ipv4_hdr* ipp;
	ipp = (struct ipv4_hdr*) buf;
	tcpp = (struct TCP_hdr*) (buf + sizeof(struct TCP_hdr));
	/*
	int start = sizeof(struct ipv4_hdr);
	for (int idx = start; idx < size; idx++) {
		printf("%c", buf[idx]);
	}
	printf("\n");
	*/

	tar_dhost = ipp->ip_dhost;

	_strstr(buf, size, str, strlen(str));

	if (strlen(wp) > 0) {
		cout << strlen(wp) << endl;
		string wps = string(wp);
		cout << "webpage: " << wps << endl;
		if (set_hp.find(wps) != set_hp.end()) {
			set_dhost.insert(tar_dhost);
			return 1;
		}
	}
	else {
		if (set_dhost.find(tar_dhost) != set_dhost.end()) {
			return 1;
		}
	}
	/*
	if (tar_dhost == 0) {
		if (_strstr(buf, size, str, strlen(str))) {
			tar_dhost = ipp->ip_dhost;
			return 1;
		}
	}
	else {
		if (tar_dhost == ipp->ip_dhost) {
			return 1;
		}
	}
	*/
	return 0;
	//printf("%x\n", ntohs(ethp->ether_type));
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		//dump(data, ret);
		net_mode = dump_analyze(data, ret);
	}

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (net_mode == 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else {
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	
	// if want to drop packet
	// return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void read_homepage(char* filename){
	ifstream read_file(filename);
	int comma_pos = 0;
	char line1[100], line2[100];
	string hp1;
	int num2 = 0;
	while(read_file.getline(line1, sizeof(line1))) {
		for (int num1 = 0; num1 < strlen(line1); num1++) {
			if (line1[num1] == ',') {
				comma_pos = num1 + 1;
				break;
			}
		}
		for (int num1 = comma_pos; num1 < strlen(line1); num1++) {
			line2[num1 - comma_pos] = line1[num1];
		}
		for (int num1 = strlen(line1) - comma_pos; num1 < sizeof(line2); num1++) {
			line2[num1] = 0;
		}
		set_hp.insert(string(line2));
		num2++;
	}
	cout << num2 << endl;
	read_file.close();
}
int main(int argc, char **argv)
{
	char* filename;
	if (argc == 2) {
		filename = argv[1];
		printf("%s\n", filename);
	}
	read_homepage(filename);
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

