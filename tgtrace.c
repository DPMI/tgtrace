#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/stream.h"
#include "caputils/filter.h"
#include "caputils/utils.h"
#include "caputils/marker.h"
#include "caputils/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/time.h>

static int keep_running = 1;
static unsigned int flags = FORMAT_REL_TIMESTAMP;
static unsigned int max_packets = 0;
static unsigned int max_matched_packets = 0;
static const char* iface = NULL;
static struct timeval timeout = {1,0};
static const char* program_name = NULL;


 struct tgdata{
    u_int32_t exp_id;
    u_int32_t run_id;
    u_int32_t key_id;
    u_int32_t counter;
    u_int64_t starttime;
    u_int64_t stoptime;
    struct timeval deptime;
    char junk[1500];
  };

void handle_sigint(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\rGot SIGINT again, terminating.\n");
		abort();
	}
	fprintf(stderr, "\rAborting capture.\n");
	keep_running = 0;
}

static const char* shortopts = "p:c:i:t:dDar1234xHh";
static struct option longopts[]= {
	{"packets",  required_argument, 0, 'p'},
	{"count",    required_argument, 0, 'c'},
	{"iface",    required_argument, 0, 'i'},
	{"timeout",  required_argument, 0, 't'},
	{"calender", no_argument,       0, 'd'},
	{"localtime",no_argument,       0, 'D'},
	{"absolute", no_argument,       0, 'a'},
	{"relative", no_argument,       0, 'r'},
	{"hexdump",  no_argument,       0, 'x'},
	{"headers",  no_argument,       0, 'H'},
	{"help",     no_argument,       0, 'h'},
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("%s-%s\n", program_name, caputils_version(NULL));
	printf("(C) 2004 Patrik Arlos <patrik.arlos@bth.se>\n");
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTIONS] STREAM\n", program_name);
	printf("  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	       "                       on. For other streams it is ignored.\n"
	       "  -p, --packets=N      Stop after N read packets.\n"
	       "  -c, --count=N        Stop after N matched packets.\n"
	       "                       If both -p and -c is used, what ever happens first will stop.\n"
	       "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	       "  -h, --help           This text.\n"
	       "\n"
	       "Formatting options:\n"
	       "  -1                   Show only DPMI information.\n"
	       "  -2                     .. include link layer.\n"
	       "  -3                     .. include transport layer.\n"
	       "  -4                     .. include application layer. [default]\n"
	       "  -H, --headers        Show layer headers.\n"
	       "  -x, --hexdump        Write full package content as hexdump.\n"
	       "  -d, --calender       Show timestamps in human-readable format (UTC).\n"
	       "  -D, --localtime      Show timestamps in human-readable format (local time).\n"
	       "  -a, --absolute       Show absolute timestamps.\n"
	       "  -r, --relative       Show timestamps relative to first packet. [default]\n"
	       "\n");
	filter_from_argv_usage();
}


static int min(int a, int b){ return a<b?a:b; }

static const char* tcp_flags(const struct tcphdr* tcp){
	static char buf[12];
	size_t i = 0;

	if (tcp->syn) buf[i++] = 'S';
	if (tcp->fin) buf[i++] = 'F';
	if (tcp->ack) buf[i++] = 'A';
	if (tcp->psh) buf[i++] = 'P';
	if (tcp->urg) buf[i++] = 'U';
	if (tcp->rst) buf[i++] = 'R';
	buf[i++] = 0;

	return buf;
}

static void tcp_options(const struct tcphdr* tcp,FILE* dst ){

	uint16_t wf=1;
	uint16_t mss;
	uint8_t SAC;
	int k;

	typedef struct {
	  u_int8_t kind;
	  u_int8_t size;
	} tcp_option_t;
	    


	if ((tcp->doff)>5){
	  int optlen=0;

	  fprintf(dst,"|");//, 4*tcp->doff-sizeof(struct tcphdr));
	  /*
	  fprintf(dst,"options %d bytes, tcp at %p with size %d \nHDR:", 4*tcp->doff,tcp,sizeof(struct tcphdr));
	  uint8_t* opt=(u_int8_t*)(tcp+sizeof(struct tcphdr));
	  for(k=0;k<44;k++){
	    fprintf(dst,"%0x ",*(opt+k));
	  }
	  fprintf(dst,"\nOPT:");
	  */
	  uint8_t* opt=(u_int8_t*)((const char*)tcp) + sizeof(struct tcphdr);
	  /*
	    for(k=0;k<10;k++){
	    fprintf(dst,"%0x ",*(opt+k));
	  }
	  */

	  //	  fprintf(dst,"\n");
	  int optcount=0;
	  while ( *opt != 0 && optlen<4*tcp->doff){
	    tcp_option_t* _opt = (tcp_option_t*)opt;

	    //	    fprintf(dst,"%p | len = %d | kind %d | len %d\n",*opt,optlen,_opt->kind,_opt->size);
	    optcount++;

	    if(_opt->kind == 0 ){ // NOP
	      fprintf(dst,"EOL|");
	      break;
	    }
	    if(_opt->kind == 1 ){ // NOP
	      fprintf(dst,"NOP|");
	      opt+=1;
	      optlen+=1;
	      continue;
	    }
	    if(_opt->kind == 2 ) { //MSS
	      typedef struct {
		u_int8_t kind;
		u_int8_t size;
		u_int16_t mss;
	      } tcpopt_mss;
	      tcpopt_mss* _mss=(tcpopt_mss*)opt;
	      mss=ntohs(_mss->mss);
	      fprintf(dst,"MSS(%d)|",mss);	     

	    }
	    if(_opt->kind == 3 ) { //Windowscale factor
	      wf=*(opt+sizeof(tcp_option_t));
	      fprintf(dst,"WS(%d)|",2<<(wf-1));

	    }
	    if(_opt->kind == 4 ) { //SAC
	      fprintf(dst,"SAC|");
	      SAC=1;
	    }
	    if(_opt->kind == 8 ) { //TSS
	      fprintf(dst,"TSS|");
	    }
	    opt+=_opt->size;
	    optlen+=_opt->size;
	  }
	}
	
}

static void print_tg(FILE* dst, const struct tgdata* payload, unsigned int flags){
  //  fputs("TG", dst);
  u_int32_t expid,keyid,runid;
  int seqnr;

  //  fprintf(dst, "TG pointer = %p ", payload);
  expid=ntohl(payload->exp_id);
  runid=ntohl(payload->run_id);
  keyid=ntohl(payload->key_id);
  seqnr=ntohl(payload->counter);
  
  fprintf(dst," TraffGen Expid/Runid/Keyid/Seqnr %zu %zu %d %d", (u_int32_t)expid,(u_int32_t)runid,(u_int32_t)keyid,(u_int32_t)seqnr);
  


}


  

static void print_tcp(FILE* dst, const struct ip* ip, const struct tcphdr* tcp, unsigned int flags){
	fputs("TCP", dst);

	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "(HDR[%d]DATA[%0x])",4*tcp->doff, ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl);
	}
	
     	fprintf(dst, " [%s] %s:%d", tcp_flags(tcp), inet_ntoa(ip->ip_src), (u_int16_t)ntohs(tcp->source));
	fprintf(dst, " --> %s:%d",inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(tcp->dest));

	fprintf(dst, " %d %lu %lu ", (u_int16_t)ntohs(tcp->window),(u_int32_t)ntohl(tcp->seq),(u_int32_t)ntohl(tcp->ack_seq));
	tcp_options(tcp,dst);

	
	if((u_int16_t)ntohs(tcp->dest)==1500){
	  //	  fprintf(dst,"TG port, udpointer = %p, sizeof (udphdr) %d --> ", udp,sizeof(struct udphdr));
	  print_tg(dst,(((const char*)tcp)+4*tcp->doff),flags);
	}

}





static void print_udp(FILE* dst, const struct ip* ip, const struct udphdr* udp, unsigned int flags){
	fputs("UDP", dst);

	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "(HDR[%zd]DATA[%zd])", sizeof(struct udphdr), ntohs(udp->len)-sizeof(struct udphdr));
	}

	const uint16_t sport = ntohs(udp->source);
	const uint16_t dport = ntohs(udp->dest);



	fprintf(dst, ": %s:%d",    inet_ntoa(ip->ip_src), sport);
	fprintf(dst, " --> %s:%d", inet_ntoa(ip->ip_dst), dport);

	if(dport==1500){
	  //	  fprintf(dst,"TG port, udpointer = %p, sizeof (udphdr) %d --> ", udp,sizeof(struct udphdr));
	  print_tg(dst,(((const char*)udp)+sizeof(struct udphdr)),flags);
	}
}

static void print_icmp(FILE* dst, const struct ip* ip, const struct icmphdr* icmp, unsigned int flags){
	fputs("ICMP", dst);
	if ( flags & FORMAT_HEADER ){
		fprintf(dst, "[Type=%d, code=%d]", icmp->type, icmp->code);
	}

	fprintf(dst, ": %s ",inet_ntoa(ip->ip_src));
	fprintf(dst, "--> %s",inet_ntoa(ip->ip_dst));

	if ( flags < (unsigned int)FORMAT_LAYER_APPLICATION ){
		return;
	}
	fputs(": ", dst);

	switch ( icmp->type ){
	case ICMP_ECHOREPLY:
		fprintf(dst, "echo reply: SEQNR = %d ", icmp->un.echo.sequence);
		break;

	case ICMP_DEST_UNREACH:
		switch ( icmp->code ){
		case ICMP_NET_UNREACH:    fprintf(dst, "Destination network unreachable"); break;
		case ICMP_HOST_UNREACH:   fprintf(dst, "Destination host unreachable"); break;
		case ICMP_PROT_UNREACH:   fprintf(dst, "Destination protocol unreachable"); break;
		case ICMP_PORT_UNREACH:   fprintf(dst, "Destination port unreachable"); break;
		case ICMP_FRAG_NEEDED:    fprintf(dst, "Fragmentation required"); break;
		case ICMP_SR_FAILED:      fprintf(dst, "Source route failed"); break;
		case ICMP_NET_UNKNOWN:    fprintf(dst, "Destination network unknown"); break;
		case ICMP_HOST_UNKNOWN:   fprintf(dst, "Destination host unknown"); break;
		case ICMP_HOST_ISOLATED:  fprintf(dst, "Source host isolated"); break;
		case ICMP_NET_ANO:        fprintf(dst, "Network administratively prohibited"); break;
		case ICMP_HOST_ANO:       fprintf(dst, "Host administratively prohibited"); break;
		case ICMP_NET_UNR_TOS:    fprintf(dst, "Network unreachable for TOS"); break;
		case ICMP_HOST_UNR_TOS:   fprintf(dst, "Host unreachable for TOS"); break;
		case ICMP_PKT_FILTERED:   fprintf(dst, "Communication administratively prohibited"); break;
		case ICMP_PREC_VIOLATION: fprintf(dst, "Host Precedence Violation"); break;
		case ICMP_PREC_CUTOFF:    fprintf(dst, "Precedence cutoff in effect"); break;
		default: fprintf(dst, "Destination unreachable (code %d)\n", icmp->code);
		}
		break;

	case ICMP_SOURCE_QUENCH:
		fprintf(dst, "source quench");
		break;

	case ICMP_REDIRECT:
		fprintf(dst, "redirect");
		break;

	case ICMP_ECHO:
		fprintf(dst, "echo reqest: SEQNR = %d ", icmp->un.echo.sequence);
		break;

	case ICMP_TIME_EXCEEDED:
		fprintf(dst, "time exceeded");
		break;

	case ICMP_TIMESTAMP:
		fprintf(dst, "timestamp request");
		break;

	case ICMP_TIMESTAMPREPLY:
		fprintf(dst, "timestamp reply");
		break;

	default:
		fprintf(dst, "Type %d\n", icmp->type);
	}
}

static void print_ipv4(FILE* dst, const struct ip* ip, unsigned int flags){
	const void* payload = ((const char*)ip) + 4*ip->ip_hl;


	switch( ip->ip_p ) {
	case IPPROTO_TCP:
	        if ( flags & FORMAT_HEADER ){
		  fprintf(dst, "(HDR[%d])[", 4*ip->ip_hl);
		  fprintf(dst, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
		  fprintf(dst, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
		  fprintf(dst, "TTL=%d:",(u_int8_t)ip->ip_ttl);
		  fprintf(dst, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));
		  if ( ntohs(ip->ip_off) & IP_DF) fprintf(dst, "DF");
		  if ( ntohs(ip->ip_off) & IP_MF) fprintf(dst, "MF");
		  fprintf(dst, " Tos:%0x]",(u_int8_t)ip->ip_tos);
		}
		//		fputs("* ", dst);
		
		print_tcp(dst, ip, (const struct tcphdr*)payload, flags);
		break;
		
	case IPPROTO_UDP:
	  print_udp(dst, ip, (const struct udphdr*)payload, flags);



	  break;

	case IPPROTO_ICMP:
	  //print_icmp(dst, ip, (const struct icmphdr*)payload, flags);
		break;

	case IPPROTO_IGMP:
	  //fprintf(dst, "IGMP");
		break;

	case IPPROTO_OSPF:
	  //fprintf(dst, "OSPF");
		break;

	default:
	  //fprintf(dst, "Unknown transport protocol: %d", ip->ip_p);
		break;
	}
}

static void print_ieee8023(FILE* dst, const struct llc_pdu_sn* llc){
	fprintf(dst,"dsap=%02x ssap=%02x ctrl1 = %02x ctrl2 = %02x", llc->dsap, llc->ssap, llc->ctrl_1, llc->ctrl_2);
}

static void print_arp(FILE* dst, const struct cap_header* cp, const struct ether_arp* arp){
	fprintf(dst, " ARP: ");

	const int format = ntohs(arp->arp_hrd);
	const int op = ntohs(arp->arp_op);

	if ( format == ARPHRD_ETHER ){
		union {
			uint8_t v[4];
			struct in_addr addr;
		} spa, tpa;
		memcpy(spa.v, arp->arp_spa, 4);
		memcpy(tpa.v, arp->arp_tpa, 4);

		switch ( op ){
		case ARPOP_REQUEST:
			fputs("Request who-has ", dst);
			fputs(inet_ntoa(tpa.addr), dst);
			fputs(" tell ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			break;

		case ARPOP_REPLY:
			fputs("Reply ", dst);
			fputs(inet_ntoa(spa.addr), dst);
			fputs(" is-at ", dst);
			fputs(hexdump_address((const struct ether_addr*)arp->arp_sha), dst);
			break;

		case ARPOP_RREQUEST:
			fputs("RARP request", dst);
			break;

		case ARPOP_RREPLY:
			fputs("RARP reply", dst);
			break;

		default:
			fprintf(dst, "Unknown op: %d", op);
		}
	} else {
		fprintf(dst, "Unknown format: %d", format);
	}

	fprintf(dst, ", length %zd", cp->len - sizeof(struct ethhdr));
}

static void print_eth(FILE* dst, const struct cap_header* cp, const struct ethhdr* eth, unsigned int flags){
	const void* payload = ((const char*)eth) + sizeof(struct ethhdr);
	uint16_t h_proto = ntohs(eth->h_proto);
	uint16_t vlan_tci;

 begin:

	switch ( h_proto ){
	case ETHERTYPE_VLAN:
		vlan_tci = ((const uint16_t*)payload)[0];
		h_proto = ntohs(((const uint16_t*)payload)[0]);
		payload = ((const char*)eth) + sizeof(struct ethhdr);
		//		fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
		goto begin;

	case ETHERTYPE_IP:
	  //fputs(" IPv4", dst);
		if ( flags >= FORMAT_LAYER_TRANSPORT ){
			print_ipv4(dst, (const struct ip*)payload, flags);
		}
		break;

	case ETHERTYPE_IPV6:
	  //	fputs(" IPv6", dst);
		break;

	case ETHERTYPE_ARP:
	  //	print_arp(dst, cp, (const struct ether_arp*)payload);
		break;

	case 0x0810:
	  //	fprintf(dst, " MP packet");
		break;

	case STPBRIDGES:
	  //	fprintf(dst, " STP(0x%04x): (spanning-tree for bridges)", h_proto);
		break;

	case CDPVTP:
	  //	fprintf(dst, " CDP(0x%04x): (CISCO Discovery Protocol)", h_proto);
		break;

	default:
	  //	fprintf(dst, " IEEE802.3 [0x%04x] ", h_proto);
	  //	fputs(hexdump_address((const struct ether_addr*)eth->h_source), dst);
	  //	fputs(" -> ", dst);
	  //	fputs(hexdump_address((const struct ether_addr*)eth->h_dest), dst);
	  //	if(h_proto<0x05DC){
	  //		fputs(" ", dst);
	  //		print_ieee8023(dst, (const struct llc_pdu_sn*)payload);
	  //	}
		break;
	}
}

static void print_timestamp(FILE* fp, struct format* state, const struct cap_header* cp){
	const int format_date  = state->flags & FORMAT_DATE_BIT;
	const int format_local = state->flags & FORMAT_LOCAL_BIT;
	const int relative     = state->flags & FORMAT_REL_TIMESTAMP;

	if( !format_date ) {
		timepico t = cp->ts;
		int sign = 0; /* quick-and-dirty solution */

		if ( relative ){
			/* need to test if timestamp is less than reference in case multiple
			 * locations is present in trace in which case dt may be negative. */
			if ( timecmp(&t, &state->ref) >= 0 ){
				t = timepico_sub(t, state->ref);
				sign = 0;
			} else {
				t = timepico_sub(state->ref, t);
				sign = 1;
			}
		}

		fprintf(fp, "%s%u.%012"PRIu64, sign ? "-" : "", t.tv_sec, t.tv_psec);
		return;
	}

	static char buffer[32];
	time_t time = (time_t)cp->ts.tv_sec;
	struct tm* tm = format_local ? localtime(&time) : gmtime(&time);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(fp, "%s.%012"PRIu64, buffer, cp->ts.tv_psec);
	strftime(buffer, sizeof(buffer), "%z", tm);
	fprintf(fp, " %s", buffer);
}

static void print_linklayer(FILE* fp, const struct cap_header* cp, unsigned int flags){
	fputc(':', fp);

	/* Test for libcap_utils marker packet */
	struct marker mark;
	int marker_port;
	if ( (marker_port=is_marker(cp, &mark, 0)) != 0 ){
		fprintf(stdout, "Marker [e=%d, r=%d, k=%d, s=%d, port=%d]",
		        mark.exp_id, mark.run_id, mark.key_id, mark.seq_num, marker_port);
		return;
	}

	print_eth(fp, cp, cp->ethhdr, flags);
}

static void print_pkt(FILE* fp, struct format* state, const struct cap_header* cp){
	print_timestamp(fp, state, cp);
	fprintf(fp, ":LINK(%4d):CAPLEN(%4d)", cp->len, cp->caplen);

	if ( state->flags >= FORMAT_LAYER_LINK ){
		print_linklayer(fp, cp, state->flags);
	}
	fputc('\n', fp);

	if ( state->flags & FORMAT_HEXDUMP ){
		hexdump(fp, cp->payload, min(cp->caplen, cp->len));
	}
}

void format_setup(struct format* state, unsigned int flags){
	state->pktcount = 0;
	state->first = 1;
	state->flags = flags;

	/* by default show all */
	if ( state->flags >> FORMAT_LAYER_BIT == 0){
		state->flags |= FORMAT_LAYER_APPLICATION;
	}
}

void format_pkg(FILE* fp, struct format* state, const struct cap_header* cp){
	fprintf(fp, "[%4"PRIu64"]:%.4s:%.8s:", state->pktcount++, cp->nic, cp->mampid);
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
	print_pkt(fp, state, cp);
}

void format_ignore(FILE* fp, struct format* state, const struct cap_header* cp){
	state->pktcount++;
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
}




int main(int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	struct filter filter;
	if ( filter_from_argv(&argc, argv, &filter) != 0 ){
		return 0; /* error already shown */
	}

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case '1':
		case '2':
		case '3':
		case '4':
		{
			const unsigned int mask = (7<<FORMAT_LAYER_BIT);
			flags &= ~mask; /* reset all layer bits */
			flags |= (op-'0')<<FORMAT_LAYER_BIT;
			break;
		}

		case 'd': /* --calender */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_UTC;
			break;

		case 'D': /* --localtime */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_LOCALTIME;
			break;

		case 'a': /* --absolute */
			flags &= ~FORMAT_REL_TIMESTAMP;
			break;

		case 'r': /* --relative */
			flags |= FORMAT_REL_TIMESTAMP;
			break;

		case 'H': /* --headers */
			flags |= FORMAT_HEADER;
			break;

		case 'p': /* --packets */
			max_packets = atoi(optarg);
			break;

		case 'c': /* --packets */
			max_matched_packets = atoi(optarg);
			break;


		case 't': /* --timeout */
		{
			int tmp = atoi(optarg);
			timeout.tv_sec  = tmp / 1000;
			timeout.tv_usec = tmp % 1000 * 1000;
		}
		break;

		case 'x': /* --hexdump */
			flags |= FORMAT_HEXDUMP;
			break;

		case 'i': /* --iface */
			iface = optarg;
			break;

		case 'h': /* --help */
			show_usage();
			return 0;

		default:
			fprintf (stderr, "%s: argument '-%c' declared but not handled\n", argv[0], op);
		}
	}

	int ret;

	/* Open stream(s) */
	struct stream* stream;
	if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, "-", program_name, 0)) != 0 ) {
		return ret; /* Error already shown */
	}
	const stream_stat_t* stat = stream_get_stat(stream);
	stream_print_info(stream, stderr);

	/* handle C-c */
	signal(SIGINT, handle_sigint);

	/* setup formatter */
	struct format format;
	format_setup(&format, flags);

	uint64_t matched = 0;
	while ( keep_running ) {
		/* A short timeout is used to allow the application to "breathe", i.e
		 * terminate if SIGINT was received. */
		struct timeval tv = timeout;

		/* Read the next packet */
		cap_head* cp;
		ret = stream_read(stream, &cp, NULL, &tv);
		if ( ret == EAGAIN ){
			continue; /* timeout */
		} else if ( ret != 0 ){
			break; /* shutdown or error */
		}

		if ( filter_match(&filter, cp->payload, cp) ){
			format_pkg(stdout, &format, cp);
			matched++;
		} else {
			format_ignore(stdout, &format, cp);
		}

		if ( max_packets > 0 && stat->matched >= max_packets) {
			/* Read enough pkts lets break. */
			break;
		}
		if ( max_matched_packets > 0 && matched >= max_matched_packets) {
			/* Read enough pkts lets break. */
			break;
		}
	}

	/* if ret == -1 the stream was closed properly (e.g EOF or TCP shutdown)
	 * In addition EINTR should not give any errors because it is implied when the
	 * user presses C-c */
	if ( ret > 0 && ret != EINTR ){
		fprintf(stderr, "stream_read() returned 0x%08X: %s\n", ret, caputils_error_string(ret));
	}

	/* Write stats */
	fprintf(stderr, "%"PRIu64" packets read.\n", stat->read);
	fprintf(stderr, "%"PRIu64" packets matched filter.\n", matched);

	/* Release resources */
	stream_close(stream);
	filter_close(&filter);

	return 0;
}
