int pcap_snapshot(pcap_t *p){
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->snapshot);
}
