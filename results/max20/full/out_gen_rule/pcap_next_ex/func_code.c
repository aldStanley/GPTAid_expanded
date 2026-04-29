int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    const u_char **pkt_data){
	struct oneshot_userdata s;

	s.hdr = &p->pcap_header;
	s.pkt = pkt_data;
	s.pd = p;

	/* Saves a pointer to the packet headers */
	*pkt_header= &p->pcap_header;

	if (p->rfile != NULL) {
		int status;

		/* We are on an offline capture */
		status = pcap_offline_read(p, 1, p->oneshot_callback,
		    (u_char *)&s);

		/*
		 * Return codes for pcap_offline_read() are:
		 *   -  0: EOF
		 *   - -1: error
		 *   - >0: OK - result is number of packets read, so
		 *         it will be 1 in this case, as we've passed
		 *         a maximum packet count of 1
		 * The first one ('0') conflicts with the return code of
		 * 0 from pcap_read() meaning "no packets arrived before
		 * the timeout expired", so we map it to -2 so you can
		 * distinguish between an EOF from a savefile and a
		 * "no packets arrived before the timeout expired, try
		 * again" from a live capture.
		 */
		if (status == 0)
			return (-2);
		else
			return (status);
	}

	/*
	 * Return codes for pcap_read() are:
	 *   -  0: timeout
	 *   - -1: error
	 *   - -2: loop was broken out of with pcap_breakloop()
	 *   - >0: OK, result is number of packets captured, so
	 *         it will be 1 in this case, as we've passed
	 *         a maximum packet count of 1
	 * The first one ('0') conflicts with the return code of 0 from
	 * pcap_offline_read() meaning "end of file".
	*/
	return (p->read_op(p, 1, p->oneshot_callback, (u_char *)&s));
}
