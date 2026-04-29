int pcap_set_promisc(pcap_t *p, int promisc){
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.promisc = promisc;
	return (0);
}
