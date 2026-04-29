pcap_t *
pcap_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision){
	pcap_t *p;

	switch (precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
	case PCAP_TSTAMP_PRECISION_NANO:
		break;

	default:
		/*
		 * This doesn't really matter, but we don't have any way
		 * to report particular errors, so the only failure we
		 * should have is a memory allocation failure.  Just
		 * pick microsecond precision.
		 */
		precision = PCAP_TSTAMP_PRECISION_MICRO;
		break;
	}
	p = malloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	memset (p, 0, sizeof(*p));
	p->snapshot = snaplen;
	p->linktype = linktype;
	p->opt.tstamp_precision = precision;
	p->can_set_rfmon_op = pcap_can_set_rfmon_dead;
	p->read_op = pcap_read_dead;
	p->inject_op = pcap_inject_dead;
	p->setfilter_op = pcap_setfilter_dead;
	p->setdirection_op = pcap_setdirection_dead;
	p->set_datalink_op = pcap_set_datalink_dead;
	p->getnonblock_op = pcap_getnonblock_dead;
	p->setnonblock_op = pcap_setnonblock_dead;
	p->stats_op = pcap_stats_dead;
#ifdef _WIN32
	p->stats_ex_op = pcap_stats_ex_dead;
	p->setbuff_op = pcap_setbuff_dead;
	p->setmode_op = pcap_setmode_dead;
	p->setmintocopy_op = pcap_setmintocopy_dead;
	p->getevent_op = pcap_getevent_dead;
	p->oid_get_request_op = pcap_oid_get_request_dead;
	p->oid_set_request_op = pcap_oid_set_request_dead;
	p->sendqueue_transmit_op = pcap_sendqueue_transmit_dead;
	p->setuserbuffer_op = pcap_setuserbuffer_dead;
	p->live_dump_op = pcap_live_dump_dead;
	p->live_dump_ended_op = pcap_live_dump_ended_dead;
	p->get_airpcap_handle_op = pcap_get_airpcap_handle_dead;
#endif
	p->breakloop_op = pcap_breakloop_dead;
	p->cleanup_op = pcap_cleanup_dead;

	/*
	 * A "dead" pcap_t never requires special BPF code generation.
	 */
	p->bpf_codegen_flags = 0;

	p->activated = 1;
	return (p);
}
