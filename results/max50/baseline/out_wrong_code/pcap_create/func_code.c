pcap_t *
pcap_create(const char *device, char *errbuf){
	size_t i;
	int is_theirs;
	pcap_t *p;
	char *device_str;

	/*
	 * A null device name is equivalent to the "any" device -
	 * which might not be supported on this platform, but
	 * this means that you'll get a "not supported" error
	 * rather than, say, a crash when we try to dereference
	 * the null pointer.
	 */
	if (device == NULL)
		device_str = strdup("any");
	else {
#ifdef _WIN32
		/*
		 * On Windows, for backwards compatibility reasons,
		 * pcap_lookupdev() returns a pointer to a sequence of
		 * pairs of UTF-16LE device names and local code page
		 * description strings.
		 *
		 * This means that if a program uses pcap_lookupdev()
		 * to get a default device, and hands that to an API
		 * that opens devices, we'll get handed a UTF-16LE
		 * string, not a string in the local code page.
		 *
		 * To work around that, we check whether the string
		 * looks as if it might be a UTF-16LE string and, if
		 * so, convert it back to the local code page's
		 * extended ASCII.
		 *
		 * We disable that check in "new API" mode, because:
		 *
		 *   1) You *cannot* reliably detect whether a
		 *   string is UTF-16LE or not; "a" could either
		 *   be a one-character ASCII string or the first
		 *   character of a UTF-16LE string.
		 *
		 *   2) Doing that test can run past the end of
		 *   the string, if it's a 1-character ASCII
		 *   string
		 *
		 * This particular version of this heuristic dates
		 * back to WinPcap 4.1.1; PacketOpenAdapter() does
		 * uses the same heuristic, with the exact same
		 * vulnerability.
		 *
		 * That's why we disable this in "new API" mode.
		 * We keep it around in legacy mode for backwards
		 * compatibility.
		 */
		if (!pcap_new_api && device[0] != '\0' && device[1] == '\0') {
			size_t length;

			length = wcslen((wchar_t *)device);
			device_str = (char *)malloc(length + 1);
			if (device_str == NULL) {
				pcap_fmt_errmsg_for_errno(errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "malloc");
				return (NULL);
			}

			snprintf(device_str, length + 1, "%ws",
			    (const wchar_t *)device);
		} else
#endif
			device_str = strdup(device);
	}
	if (device_str == NULL) {
		pcap_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		return (NULL);
	}

	/*
	 * Try each of the non-local-network-interface capture
	 * source types until we find one that works for this
	 * device or run out of types.
	 */
	for (i = 0; capture_source_types[i].create_op != NULL; i++) {
		is_theirs = 0;
		p = capture_source_types[i].create_op(device_str, errbuf,
		    &is_theirs);
		if (is_theirs) {
			/*
			 * The device name refers to a device of the
			 * type in question; either it succeeded,
			 * in which case p refers to a pcap_t to
			 * later activate for the device, or it
			 * failed, in which case p is null and we
			 * should return that to report the failure
			 * to create.
			 */
			if (p == NULL) {
				/*
				 * We assume the caller filled in errbuf.
				 */
				free(device_str);
				return (NULL);
			}
			p->opt.device = device_str;
			return (p);
		}
	}

	/*
	 * OK, try it as a regular network interface.
	 */
	p = pcap_create_interface(device_str, errbuf);
	if (p == NULL) {
		/*
		 * We assume the caller filled in errbuf.
		 */
		free(device_str);
		return (NULL);
	}
	p->opt.device = device_str;
	return (p);
}
