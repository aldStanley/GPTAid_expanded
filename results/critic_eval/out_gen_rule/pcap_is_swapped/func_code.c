int pcap_is_swapped(pcap_t *p){
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->swapped);
}
