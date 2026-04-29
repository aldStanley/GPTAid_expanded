int pcap_set_tstamp_type(pcap_t *p, int tstamp_type){
	int i;

	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);

	/*
	 * The argument should have been u_int, but that's too late
	 * to change now - it's an API.
	 */
	if (tstamp_type < 0)
		return (PCAP_WARNING_TSTAMP_TYPE_NOTSUP);

	/*
	 * If p->tstamp_type_count is 0, we only support PCAP_TSTAMP_HOST;
	 * the default time stamp type is PCAP_TSTAMP_HOST.
	 */
	if (p->tstamp_type_count == 0) {
		if (tstamp_type == PCAP_TSTAMP_HOST) {
			p->opt.tstamp_type = tstamp_type;
			return (0);
		}
	} else {
		/*
		 * Check whether we claim to support this type of time stamp.
		 */
		for (i = 0; i < p->tstamp_type_count; i++) {
			if (p->tstamp_type_list[i] == (u_int)tstamp_type) {
				/*
				 * Yes.
				 */
				p->opt.tstamp_type = tstamp_type;
				return (0);
			}
		}
	}

	/*
	 * We don't support this type of time stamp.
	 */
	return (PCAP_WARNING_TSTAMP_TYPE_NOTSUP);
}
