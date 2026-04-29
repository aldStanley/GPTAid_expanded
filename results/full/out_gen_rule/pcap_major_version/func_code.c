int pcap_major_version(pcap_t *p){
	if (!p->activated)
		return (PCAP_ERROR_NOT_ACTIVATED);
	return (p->version_major);
}
