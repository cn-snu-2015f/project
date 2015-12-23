#include <stdio.h> //printf
#include <stdlib.h> //exit(0)
#include <string.h> //memset
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h> //socket
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h> //nanosleep

#define BUFSIZE 2048 * 2048

#define MY_IP_ADDR "192.168.1.216"
#define IP_DF 0x4000
#define WINDOW_SIZE 2920
int id = 1111;

// pcap file descriptor
pcap_dumper_t *p_output;
int use_pcap = 0;

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/

void print_iphdr( struct iphdr *iph ){

    // Computing IP address translation from 32 bits words to 4*8bits decimal
    /* NOTE ON THE LENGTHS
    all lengths used in headers are specified in 32bits words
    thus, to print the size in bytes, we need to multiply this value by 4
    */

    // display IP HEADERS : ip.h line 45
    // ntohs convert short unsigned int, ntohl do the same for long unsigned int
    fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; "
        ,iph->version, iph->ihl*4, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), iph->ttl, iph->protocol);

    char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
    fprintf(stdout,"saddr=%s; ",saddr);

    char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
    fprintf(stdout,"daddr=%s}\n",daddr);


}

void print_tcphdr( struct tcphdr *tcp ){
   
    /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
    words that represent the header size. Therfore to get the number of bytes
    multiple this number by 4 */
    //int tcphdr_size = (tcp->doff << 2); 

    /* to print the TCP headers, we access the structure defined in tcp.h line 89
    and convert values from hexadecimal to ascii */
    fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u; window=%u; urg=%u}\n", ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, ntohs(tcp->window), tcp->urg_ptr);
}

void print_udphdr( struct udphdr * udp ){
    fprintf(stdout,"UDP{sport=%u; dport=%u; len=%u}\n",
    ntohs(udp->source), ntohs(udp->dest), udp->len);
}

void print_pkt_raw( unsigned char * nf_packet, int len){
    int i;
    for(i=0;i<len;i++){
        if( i%8 == 0)
            printf("\n");
        printf("%04x",(int)*(nf_packet+i));
    }
    printf("\n");
    return;
}

struct pseudo_header
{
    u_int32_t source_ip;
    u_int32_t dest_ip;
    u_int8_t reserved;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
 

unsigned short ipcsum(unsigned short *buf, int nwords) 
{
    // iphdr->check should be 0
    unsigned long sum;
    for(sum=0; nwords>0; nwords--){
        sum += *buf++;
        //printf("%x %x\n",(unsigned short)(sum >> 16),(unsigned short)(sum&0xffff));
        sum = (sum >> 16) + (sum &0xffff);
    }
    return (unsigned short)(~sum);
}

unsigned short tcpcsum(char * datagram, u_int16_t data_len)
{
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    char for_cal[4096];
    struct pseudo_header *psh = (struct pseudo_header *) for_cal;

    memcpy(&psh->source_ip, &iph->saddr, sizeof(u_int32_t));
    memcpy(&psh->dest_ip, &iph->daddr, sizeof(u_int32_t));
    memset(&psh->reserved, 0, 8);
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(data_len);

    memcpy(for_cal + sizeof(struct pseudo_header), tcph, data_len);

/*
    printf("%d\n",sizeof (struct iphdr));
    printf("printing datagram\n");
    print_pkt_raw( datagram, data_len + 20);
    printf("printing iph\n");
    print_pkt_raw( iph, 20);
    printf("printing tcph\n");
    print_pkt_raw( tcph, data_len);
    printf("printing for_cal data\n");
    print_pkt_raw( for_cal, data_len + sizeof(struct pseudo_header));
*/
    return ipcsum((unsigned short *)for_cal, (sizeof(struct pseudo_header) + data_len)/2);
}

void debug_mycsum(struct nfq_data* nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    u_int16_t tcp_seq_len = len - 20;

    int i;

    // copy ip header
    memcpy(iph, nf_packet, sizeof(struct iphdr));

    // copy tcp header
    // if TCP
    struct tcphdr * nf_packet_tcphdr = nf_packet + (iph->ihl << 2);
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        memcpy(tcph, nf_packet_tcphdr, tcp_seq_len);
    }    
/*
    printf("==== ip header checksum answer : %u, %x\n", ntohs(iph->check), iph->check);
    iph->check = 0;
    printf("==== my ipcsum function calculation result : %u\n", ntohs(ipcsum((unsigned short *) datagram, 10)));
    printf("=== tcp header checksum answer : %u, %x\n", ntohs(tcph->check), tcph->check);
    tcph->check = 0;
    printf("=== my tcpcsum function calculation result : %u\n", ntohs(tcpcsum(datagram, tcp_seq_len)));
*/
    return;
} 

int s; //socket for fake ACK

int sendFakeACK(struct nfq_data* nfa){
    
    char datagram[4096], source_ip[32], *data, *pseudogram;
    memset (datagram, 0, 4096);
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;
 
    // get packet information
    char *nf_packet;
    int payload_len = nfq_get_payload(nfa, &nf_packet);

    // we're sending ACK, so no data

    // copy ip header
    memcpy(iph, nf_packet, sizeof(struct iphdr));

    // fix ip header
    u_int16_t ori_tot_len = ntohs(iph->tot_len);
    struct iphdr * nf_packet_iphdr = nf_packet;
    memcpy(&iph->saddr, &nf_packet_iphdr->daddr, sizeof(u_int32_t));
    memcpy(&iph->daddr, &nf_packet_iphdr->saddr, sizeof(u_int32_t));
    iph->ttl = 64;
    iph->tot_len = htons(12+sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->check = 0;
    iph->frag_off |= htons(IP_DF);
    iph->check = ipcsum((unsigned short *) datagram, 10); //because ip header is always 20 byte / 2 byte
    iph->id = htons(id++);
	{
		uint32_t temp_addr;
		inet_aton(MY_IP_ADDR, &temp_addr);
		if (iph->saddr % 0x1000000 != temp_addr % 0x1000000){
			printf("saddr: %x\n", iph->saddr);
			printf("saddr is not in subnet\n");
//			free(iph);
			return -1;
		}
	}
    // copy tcp header
    // if TCP
    struct tcphdr * nf_packet_tcphdr = nf_packet + (iph->ihl << 2);
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        memcpy(tcph, nf_packet_tcphdr, sizeof(struct tcphdr));
    }
    // if not TCP
    else{
        printf("-- turns out it's not tcp -- : %u\n",iph->protocol);
        return 0;
    }

    // fix tcp header
    memcpy(&tcph->source, &nf_packet_tcphdr->dest, sizeof(u_short));
    memcpy(&tcph->dest, &nf_packet_tcphdr->source, sizeof(u_short));
    memcpy(&tcph->ack_seq, &nf_packet_tcphdr->seq, sizeof(u_int32_t));
    memcpy(&tcph->seq, &nf_packet_tcphdr->ack_seq, sizeof(u_int32_t));
    u_int32_t tcp_len = 0;
    tcph->psh = 0;
    if(tcph->syn == 1){
        tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + 1);
        if(tcph->ack == 1)
            tcph->syn = 0;
    }
    else if((tcph->fin == 1) && (tcph->ack == 1)){
        tcph->fin = 0;
        tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + 1);
    }
    else{
        printf("%u\n",4*(iph->ihl+tcph->doff));
        tcph->ack_seq = htonl(ntohl(tcph->ack_seq) + ori_tot_len - 4*(iph->ihl+tcph->doff));
    }
    tcph->ack = 1;
    tcph->window = htons(WINDOW_SIZE);
//    tcph->ack_seq = tcph->ack_seq + tcph->doff;
    tcph->check = 0;
    tcph->check = tcpcsum((unsigned short *) datagram, sizeof( struct tcphdr));

    // setup sin
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = inet_ntoa(*(struct in_addr *)&iph->daddr);

    //print before sending
    printf("-- Sending Fake ACK --\n");
    print_iphdr(iph);
    print_tcphdr(tcph);

	datagram[40] = 1;
	datagram[41] = 1;

     
    //Send the packet
    if (sendto (s, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
//		printf("sento failed\n");
//		free(iph);
//		free(tcph);
        perror("sendto failed");
	}
    else
	{
//		printf("send ok\n");
//		free(iph);
//		free(tcph);
        printf ("Packet Send. Length : %d \n\n" , ntohs(iph->tot_len));
	}
     
    return 1;
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	u_int32_t mark,ifi;
	int ret;
    char *nf_packet;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph){
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
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

	ret = nfq_get_payload(tb, &nf_packet);
	if ((ret >= 0)){
		printf("payload_len=%d bytes", ret);
    		fputc('\n', stdout);
    	}

    // parse the packet headers
    struct iphdr *iph = ((struct iphdr *) nf_packet);
    print_iphdr(iph);
    // if protocol is tcp
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        struct tcphdr *tcp = ((struct tcphdr *) (nf_packet + (iph->ihl << 2)));
        print_tcphdr(tcp);
    }

    // if protocol is udp
    if(iph->protocol == 17){
        struct udphdr *udp = ((struct udphdr *) (nf_packet + (iph->ihl << 2)));
        print_udphdr(udp);
    }

    fprintf(stdout,"\n");

	return id;
}

static u_int32_t record_pkt (struct nfq_data *tb){

	/*! create pcap specific header
	 */
	struct pcap_pkthdr phdr;

	/*! init capture time
	 */
	static struct timeval t;
	memset (&t, 0, sizeof(struct timeval));
	gettimeofday(&t, NULL);
	phdr.ts.tv_sec = t.tv_sec;
	phdr.ts.tv_usec = t.tv_usec;

    /*! populate pcap struct with packet headers
     */
    char *nf_packet;
	phdr.caplen = nfq_get_payload(tb,&nf_packet);
	phdr.len = phdr.caplen;

	/*! dump packet data to the file */
	pcap_dump((u_char *)p_output, &phdr, (const u_char *)nf_packet);

    return 0;
}

int is_input(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    struct tcphdr * tcph = (struct tcphdr *) (nf_packet + sizeof(struct iphdr));
    int is_input = ( strcmp(inet_ntoa(*(struct in_addr *)&iph->saddr),MY_IP_ADDR) );
//    printf("my ip addr : %s\n", MY_IP_ADDR);
//    printf("iph->saddr : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
    return is_input;
}

int is_ack(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    struct tcphdr * tcph = (struct tcphdr *) (nf_packet + sizeof(struct iphdr));
    return (tcph->ack) * (ntohs(iph->tot_len) == 52);
}

int is_syn(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    struct tcphdr * tcph = (struct tcphdr *) (nf_packet + sizeof(struct iphdr));
    return (tcph->syn);
}

int is_fin(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    struct tcphdr * tcph = (struct tcphdr *) (nf_packet + sizeof(struct iphdr));
    return (tcph->fin);
}

int is_rst(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    struct tcphdr * tcph = (struct tcphdr *) (nf_packet + sizeof(struct iphdr));
    return (tcph->rst);
}

int is_fake(struct nfq_data *nfa){
    char *nf_packet;
    u_int16_t len = nfq_get_payload(nfa, &nf_packet);
    struct iphdr * iph = (struct iphdr *)nf_packet;
    u_int16_t local_id = ntohs(iph->id);
    if(id >= local_id){
        return (id - local_id) < 10;
    }
    else{
        return (local_id - id) < 10;
    }
}

struct timespec tim, tim2;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    if(use_pcap == 1)
        record_pkt(nfa);

//    debug_mycsum(nfa);

    unsigned char *nf_packet;
    u_int32_t len = nfq_get_payload(nfa, &nf_packet);    

    // classify packet
    if(is_input(nfa)){
        if(is_syn(nfa) && is_ack(nfa)){
            sendFakeACK(nfa);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else if(is_syn(nfa)){
            sendFakeACK(nfa);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else if(is_fin(nfa) && is_ack(nfa)){
            sendFakeACK(nfa);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else if(is_rst(nfa)){
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else if(is_ack(nfa)){
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else{
            sendFakeACK(nfa);
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
    }
    else{
        if(is_fake(nfa)){
            return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
        }
        else{
            if(is_fin(nfa) && is_ack(nfa)){
                 return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
            }
            else if(is_rst(nfa)){
                 return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
            }
            else if(is_ack(nfa)){
                 printf("^^^^ dropped ^^^^\n");
                 return nfq_set_verdict(qh, id, NF_DROP, len, nf_packet);
            }
            else{
                 return nfq_set_verdict(qh, id, NF_ACCEPT, len, nf_packet);
            }
        }
    }
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
    int argument;
	char buf[BUFSIZE];
    char *pcap_destination;
    pcap_t *pd;

    //setup delay
    tim.tv_sec = 0;
    tim.tv_nsec = 100000;

    // socket for fake ACK
    s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if( s == -1 ){
        printf("Failed to create socket for fake ACK\n");
        exit(1);
    }


    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

	/*! process arguments
	 */
	while ( -1 != (argument = getopt (argc, argv, "o:h")))
	{
		switch (argument)
		{
			case 'o' :
				pcap_destination = (char *) malloc(strlen(optarg) * sizeof(char));
                memcpy(pcap_destination,optarg,strlen(optarg));
				fprintf(stdout,"pcap recording into %s\n",pcap_destination);
                use_pcap = 1;
                break;
            case 'h':
                fprintf(stdout,"nfqueue_recorder: record/display traffic passing through a netfilter queue\n\n"
                    "-h: this help\n"
                    "-o <file> : record in pcap <file>\n"
                    "\nroute traffic to it using the NFQUEUE target\n"
                    "\tiptables -I INPUT -p tcp --dport 443 -j NFQUEUE\n"
                    "\tiptables -I FORWARD -j NFQUEUE\n"
                    "\nex: ./nfqueue_recorder -o traffic.pcap\n");
                return 0;
            default:
                fprintf(stdout,"use -h for help\n");
                return -1;
        }
    }

    /*! open dump file
    * using DLT_RAW because iptables does not give us datalink layer
    */
    if(use_pcap == 1){
        fprintf(stdout,"opening pcap file at %s\n",pcap_destination);
	    pd = pcap_open_dead(DLT_RAW, BUFSIZE);
    	p_output = pcap_dump_open(pd,pcap_destination);
	    if (!p_output){
            fprintf(stderr, "error while opening pcap file\n");
            exit(1);
        }
    }

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

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("-- New packet received on queue --\n");

		nfq_handle_packet(h, buf, rv);
	}
/*
	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
/*
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif
*/
	printf("closing library handle\n");
        perror("recv error");
	nfq_close(h);

	exit(0);
}
