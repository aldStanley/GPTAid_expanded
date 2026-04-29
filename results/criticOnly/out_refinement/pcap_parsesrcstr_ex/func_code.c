int pcap_parsesrcstr_ex(const char *source, int *type, char *userinfo, char *host,
    char *port, char *name, unsigned char *uses_ssl, char *errbuf){
	char *scheme, *tmpuserinfo, *tmphost, *tmpport, *tmppath;

	/* Initialization stuff */
	if (userinfo)
		*userinfo = '\0';
	if (host)
		*host = '\0';
	if (port)
		*port = '\0';
	if (name)
		*name = '\0';
	if (uses_ssl)
		*uses_ssl = 0;

	/* Parse the source string */
	if (pcap_parse_source(source, &scheme, &tmpuserinfo, &tmphost,
	    &tmpport, &tmppath, errbuf) == -1) {
		/*
		 * Fail.
		 */
		return (-1);
	}

	if (scheme == NULL) {
		/*
		 * Local device.
		 */
		if (name && tmppath)
			pcap_strlcpy(name, tmppath, PCAP_BUF_SIZE);
		if (type)
			*type = PCAP_SRC_IFLOCAL;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		return (0);
	}

	int is_rpcap = 0;
	if (strcmp(scheme, "rpcaps") == 0) {
		is_rpcap = 1;
		if (uses_ssl) *uses_ssl = 1;
	} else if (strcmp(scheme, "rpcap") == 0) {
		is_rpcap = 1;
	}

	if (is_rpcap) {
		/*
		 * rpcap[s]://
		 *
		 * pcap_parse_source() has already handled the case of
		 * rpcap[s]://device
		 */
		if (userinfo && tmpuserinfo)
			pcap_strlcpy(userinfo, tmpuserinfo, PCAP_BUF_SIZE);
		if (host && tmphost)
			pcap_strlcpy(host, tmphost, PCAP_BUF_SIZE);
		if (port && tmpport)
			pcap_strlcpy(port, tmpport, PCAP_BUF_SIZE);
		if (name && tmppath)
			pcap_strlcpy(name, tmppath, PCAP_BUF_SIZE);
		if (type)
			*type = PCAP_SRC_IFREMOTE;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		free(scheme);
		return (0);
	}

	if (strcmp(scheme, "file") == 0) {
		/*
		 * file://
		 */
		if (name && tmppath)
			pcap_strlcpy(name, tmppath, PCAP_BUF_SIZE);
		if (type)
			*type = PCAP_SRC_FILE;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		free(scheme);
		return (0);
	}

	/*
	 * Neither rpcap: nor file:; just treat the entire string
	 * as a local device.
	 */
	if (name)
		pcap_strlcpy(name, source, PCAP_BUF_SIZE);
	if (type)
		*type = PCAP_SRC_IFLOCAL;
	free(tmppath);
	free(tmpport);
	free(tmphost);
	free(tmpuserinfo);
	free(scheme);
	return (0);
}
