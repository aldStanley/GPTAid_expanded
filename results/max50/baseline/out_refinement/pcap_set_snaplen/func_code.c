int pcap_set_snaplen(pcap_t *p, int snaplen){
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->snapshot = snaplen;
	return (0);
}
