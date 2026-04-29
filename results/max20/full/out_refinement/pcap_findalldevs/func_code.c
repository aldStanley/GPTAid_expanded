int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf){
	size_t i;
	pcap_if_list_t devlist;

	/*
	 * Find all the local network interfaces on which we
	 * can capture.
	 */
	devlist.beginning = NULL;
	if (pcap_platform_finddevs(&devlist, errbuf) == -1) {
		/*
		 * Failed - free all of the entries we were given
		 * before we failed.
		 */
		if (devlist.beginning != NULL)
			pcap_freealldevs(devlist.beginning);
		*alldevsp = NULL;
		return (-1);
	}

	/*
	 * Ask each of the non-local-network-interface capture
	 * source types what interfaces they have.
	 */
	for (i = 0; capture_source_types[i].findalldevs_op != NULL; i++) {
		if (capture_source_types[i].findalldevs_op(&devlist, errbuf) == -1) {
			/*
			 * We had an error; free the list we've been
			 * constructing.
			 */
			if (devlist.beginning != NULL)
				pcap_freealldevs(devlist.beginning);
			*alldevsp = NULL;
			return (-1);
		}
	}

	/*
	 * Return the first entry of the list of all devices.
	 */
	*alldevsp = devlist.beginning;
	return (0);
}
