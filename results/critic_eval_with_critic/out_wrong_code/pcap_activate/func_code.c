int pcap_activate(pcap_t *p){
	int status;

	/*
	 * Catch attempts to re-activate an already-activated
	 * pcap_t; this should, for example, catch code that
	 * calls pcap_open_live() followed by pcap_activate(),
	 * as some code that showed up in a Stack Exchange
	 * question did.
	 */
	if (pcap_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	status = p->activate_op(p);
	if (status >= 0) {
		/*
		 * If somebody requested non-blocking mode before
		 * calling pcap_activate(), turn it on now.
		 */
		if (p->opt.nonblock) {
			status = p->setnonblock_op(p, 1);
			if (status < 0) {
				/*
				 * Failed.  Undo everything done by
				 * the activate operation.
				 */
				p->cleanup_op(p);
				initialize_ops(p);
				return (status);
			}
		}
		p->activated = 1;
	} else {
		if (p->errbuf[0] == '\0') {
			/*
			 * No error message supplied by the activate routine;
			 * for the benefit of programs that don't specially
			 * handle errors other than PCAP_ERROR, return the
			 * error message corresponding to the status.
			 */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s",
			    pcap_statustostr(status));
		}

		/*
		 * Undo any operation pointer setting, etc. done by
		 * the activate operation.
		 */
		initialize_ops(p);
	}
	return (status);
}
