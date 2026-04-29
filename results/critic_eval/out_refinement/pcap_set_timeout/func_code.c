int pcap_set_timeout(pcap_t *p, int timeout_ms){
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.timeout = timeout_ms;
	return (0);
}
