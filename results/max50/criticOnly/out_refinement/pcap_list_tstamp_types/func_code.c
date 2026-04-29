int pcap_list_tstamp_types(pcap_t *p, int **tstamp_typesp){
	if (p->tstamp_type_count == 0) {
		/*
		 * We don't support multiple time stamp types.
		 * That means the only type we support is PCAP_TSTAMP_HOST;
		 * set up a list containing only that type.
		 */
		*tstamp_typesp = (int*)malloc(sizeof(**tstamp_typesp));
		if (*tstamp_typesp == NULL) {
			pcap_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (PCAP_ERROR);
		}
		**tstamp_typesp = PCAP_TSTAMP_HOST;
		return (1);
	} else {
		*tstamp_typesp = (int*)calloc(sizeof(**tstamp_typesp),
		    p->tstamp_type_count);
		if (*tstamp_typesp == NULL) {
			pcap_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (PCAP_ERROR);
		}
		(void)memcpy(*tstamp_typesp, p->tstamp_type_list,
		    sizeof(**tstamp_typesp) * p->tstamp_type_count);
		return (p->tstamp_type_count);
	}
}
